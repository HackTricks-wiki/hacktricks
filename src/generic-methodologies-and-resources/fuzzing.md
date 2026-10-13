# 퍼징 방법론

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: 커버리지 vs. 의미론

**Mutational Grammar Fuzzing**에서는 입력이 **문법적으로 유효한** 상태를 유지하도록 변형합니다. 커버리지 기반 모드에서는 **새 커버리지**를 유발하는 샘플만 corpus seed로 저장합니다. **언어 대상**(parser, interpreter, engine)의 경우, 한 구문의 출력이 다른 구문의 입력이 되는 **의미론적/데이터 흐름 체인**이 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**실패 유형:** fuzzer가 각각 `document()`와 `generate-id()`(또는 유사한 기본 요소)를 실행하는 seed를 찾지만, **연결된 데이터 흐름은 보존하지 못합니다**. 따라서 버그에 더 가까운 샘플도 커버리지를 늘리지 못해 버려집니다. **3개 이상의 종속 단계**에서는 무작위 재조합에 비용이 많이 들고, 커버리지 피드백도 탐색을 유도하지 못합니다.<sup>[[1]](#references)</sup>

**시사점:** 종속성이 많은 문법에서는 **변이 단계와 생성 단계를 결합**하거나, 커버리지뿐만 아니라 **함수 체이닝** 패턴을 우선 생성하도록 유도하는 방안을 고려하세요.<sup>[[1]](#references)</sup>

## Corpus 다양성 관련 주의점

커버리지 기반 변이는 **탐욕적**입니다. 새 커버리지를 달성한 샘플은 대개 변경되지 않은 큰 영역을 그대로 유지한 채 즉시 저장됩니다. 시간이 지나면 corpus에 구조적 다양성이 낮은 **거의 중복된 샘플**이 쌓입니다. 지나치게 공격적인 최소화는 유용한 맥락을 제거할 수 있으므로, 실용적인 절충안은 **최소 token 수에 도달하면 중단하는 문법 인식 최소화**입니다. 이렇게 하면 잡음을 줄이면서 변이에 적합한 주변 구조를 충분히 유지할 수 있습니다.<sup>[[1]](#references)</sup>

변이 기반 fuzzing에서 실용적인 corpus 구성 원칙은 다음과 같습니다. 거의 중복된 샘플을 많이 모으기보다, **커버리지를 최대화하는 구조적으로 다양한 seed를 소수만 유지**하세요. 실제로는 보통 다음을 의미합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **실제 샘플**(공개 corpus, 크롤링 데이터, 캡처한 트래픽, 대상 생태계의 파일 집합)에서 시작합니다.
- 유효한 샘플을 전부 보관하는 대신 **커버리지 기반 corpus 최소화**를 수행합니다.
- 변이가 무관한 바이트에 대부분의 시간을 쓰지 않고 의미 있는 필드를 대상으로 하도록 seed를 **충분히 작게** 유지합니다.
- 주요 harness/instrumentation 변경 후에는 corpus 최소화를 다시 실행합니다. 도달 가능성이 달라지면 “최적” corpus도 바뀌기 때문입니다.

## Magic Value를 위한 비교 인식 변이

fuzzer가 더 이상 진전을 보이지 않는 흔한 원인은 문법이 아니라 **엄격한 비교**입니다. 예를 들어 magic byte, 길이 검사, enum 문자열, checksum, `memcmp`, switch table 또는 연쇄 비교로 보호되는 parser dispatch 값이 있습니다. 순수한 무작위 변이는 이런 값을 바이트 단위로 추측하느라 사이클을 낭비합니다.

이러한 대상에는 **비교 추적**을 사용하세요. 예를 들어 AFL++ `CMPLOG` / Redqueen 방식의 워크플로를 이용하면 fuzzer가 실패한 비교의 피연산자를 관찰하고, 비교를 통과하는 값 쪽으로 변이를 유도할 수 있습니다.<sup>[[3]](#references)</sup>

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

- 대상이 **파일 시그니처**, **프로토콜 동사**, **타입 태그** 또는 **버전에 따라 달라지는 기능 비트** 뒤에 복잡한 로직을 숨기는 경우 특히 유용합니다.
- 실제 샘플, 프로토콜 명세 또는 디버그 로그에서 추출한 **사전**과 함께 사용하세요. 문법 토큰, 청크 이름, 동사, 구분자가 담긴 작은 사전이 방대한 범용 단어 목록보다 유용한 경우가 많습니다.
- 대상이 순차적으로 여러 검사를 수행한다면, 가장 먼저 나오는 “magic” 비교부터 통과한 다음 결과 코퍼스를 다시 최소화하여 이후 단계가 이미 유효한 접두부에서 시작하도록 하세요.

## 파일 이름 언어를 숨긴 File API Fuzzing

`filename`, `path` 또는 `URL`이라는 매개변수는 단순히 파일을 찾는 것이 아니라 인터프리터 진입점일 수 있습니다. 예를 들어 CFITSIO Extended Filename Syntax (EFS)는 열린 객체를 반환하기 전에 대괄호로 묶인 선택자, 행/픽셀 식, 계산된 열, 히스토그램, 변환을 평가합니다. 일부 형식은 임시 복사본도 만듭니다. 공격 표면을 매핑할 때 각 open/import API를 **literal-path** 또는 **interpreted-path**로 분류한 다음, 애플리케이션이 실제로 호출하는 운영 환경의 진입점을 대상으로 퍼징하세요.<sup>[[20]](#references)[[22]](#references)</sup>

그 결과로 얻는 SSRF, 파일 복사, 프로토콜 핸들러 프리미티브와 더 안전한 literal-path API는 [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)를 참조하세요.<sup>[[20]](#references)</sup>

### 백업 객체와 퍼징 대상 프로그램을 분리하세요

문법이 파일 이름 접미부에 있다면 참조된 파일의 바이트만 변이해서는 파서를 테스트할 수 없습니다. 대신 작은 하네스가 각 테스트 케이스를 문자열로 읽어 interpreted open API에 전달할 수 있습니다. CFITSIO 캠페인은 `fits_open_file()`을 읽기 전용 모드로 호출해 대부분의 EFS 파서와 평가기에 도달했습니다. 유효한 백업 파일은 별도로 준비해 두어, 기본 경로를 계속 손상시키는 대신 선택자/식 언어에 변이를 집중할 수 있도록 하세요.<sup>[[22]](#references)</sup>

각기 다른 문법 계열에 도달하는 시드를 사용한 다음, 명세와 렉서/파서 소스에서 간결한 사전을 만드세요. 입력이 반복해서 같은 구문 오류 경로에서 실패해 커버리지 증가가 멈춘다면, 무작위 변이 시간을 늘리기만 하기보다 유효한 접두부를 보존하고 구분자, 연산자, 키워드, 함수 이름, 대표 필드 이름을 추가하세요.<sup>[[22]](#references)</sup>

예를 들어 문법 사전을 사용해 하네스를 실행하세요:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness 부작용 억제

라이브러리의 read-only 플래그가 testcase의 부작용이 없음을 보장하지는 않습니다. filename 언어가 입력을 다시 쓰거나, 출력 파일을 만들거나, 임시 객체를 구체화할 수 있습니다. CFITSIO 캠페인에서는 처음에 seed 파일이 파괴되고 파일시스템 곳곳에 예상치 못한 파일이 남아 정리와 격리가 필요했습니다.<sup>[[22]](#references)</sup>

- 각 worker에 폐기 가능한 작업 디렉터리와 전용 임시 디렉터리를 제공합니다.
- 정식 backing 파일의 복사본을 노출하고, 대상이 corpus의 유일한 복사본을 변경하지 못하게 합니다.
- 원격 backend가 의도한 대상이 아니라면 네트워크 액세스를 비활성화하고, 컨테이너, mount namespace 또는 이에 준하는 sandbox로 쓰기 가능한 경로를 제한합니다.
- 각 실행 또는 worker batch가 끝날 때 디렉터리를 초기화하고, 예상치 못한 파일시스템 변경을 추가 finding으로 취급합니다.

### Crash-to-patch-to-fuzz 루프

수천 개의 artifact가 수천 개의 patch 작업으로 이어지지 않도록 수정 전에 crash를 클러스터링합니다. CFITSIO 평가에서 AFLTriage는 초기 crash 집합을 몇 가지 근본 원인으로 줄였습니다. 이후 공개된 advisory에는 잘못된 대상 크기 검사, `realloc()` 후 오래된 포인터, 산술 오류, 안전하지 않은 parser 정리 경로 등 서로 다른 실패가 나타납니다.<sup>[[21]](#references)[[22]](#references)</sup>

1. 각 클러스터에서 대표 입력을 최소화하고 AddressSanitizer를 사용해 재현합니다.
2. 실패한 정확한 메모리 접근, 소스 위치, 할당/해제 이력, 그리고 invariant가 깨지게 된 parser 상태를 기록합니다.
3. 범위를 좁힌 후보 patch 하나를 적용하고 동일한 coverage 및 sanitizer 계측으로 다시 빌드합니다.
4. 원래 reproducer와 해당 클러스터의 **모든 입력**을 재생합니다. 메모리 안전성 수정으로 오류 경로의 소유권 처리가 깨질 수 있으므로 leak detection도 활성화합니다.
5. 실제 파일로 functional test를 실행한 다음 누적된 queue에서 재개합니다. (엔진이 바이너리 변경 후 새 output directory를 요구한다면 해당 queue를 다시 가져옵니다.)
6. 반복합니다. 첫 번째 얕은 crash를 제거하면 기존 seed가 더 깊은 parser 상태까지 진행하는 경우가 많습니다.

LLM은 crash를 일으킨 입력, sanitizer 보고서, harness, 관련 소스가 제공되면 2단계를 가속하고 3단계 patch 초안을 작성할 수 있지만, 해당 patch는 신뢰할 수 없는 상태로 남습니다. 수정 수용 여부는 모델의 설명이 아니라 sanitizer 재생과 regression gate로 결정해야 합니다.<sup>[[22]](#references)</sup>

## Edge Coverage로 구분되지 않는 경로에 더 풍부한 피드백 제공

일반적인 edge coverage는 두 실행이 서로 다른 caller를 통해 같은 helper를 지나거나 함수 내부에서 서로 다른 branch 조합을 선택하는 경우를 구분할 수 없습니다. 공유 decoder, protocol dispatcher, interpreter helper에서는 edge에 이르는 **경로**에 따라 활성 상태가 달라지므로 중요합니다. 모든 calling context를 무작정 추적하는 것도 위험합니다. coverage map과 queue가 폭발적으로 커질 수 있기 때문입니다. 따라서 context-sensitive fuzzing 연구는 전체 call graph를 context-sensitive하게 처리하기보다 유망한 context만 세분화할 것을 권장합니다.<sup>[[14]](#references)</sup>

최신 AFL++ 빌드는 일반적인 edge coverage 외에 **함수별 Ball-Larus 경로 coverage**를 제공합니다. 함수 내 각 비순환 경로에 feature를 할당하며, loop back-edge는 제거되므로 이 피드백은 branch 조합은 구분하지만 **loop 반복 횟수는 구분하지 않습니다**. 완화된 level `1`부터 시작한 뒤, 경로 수가 기하급수적으로 늘어날 수 있으므로 더 엄격한 모드는 의심스러운 parser/state-machine 코드에만 적용합니다.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

보안과 관련된 여러 지점에서 호출되는 helper의 경우, LTO 모드는 각 함수 경로를 바로 호출하는 지점과 결합할 수 있습니다:<sup>[[13]](#references)</sup>

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

**캠페인 지침:** 더 풍부한 피드백은 신중하게 적용하고, 커버리지 맵/큐 비용을 모니터링하세요.<sup>[[13]](#references)[[14]](#references)</sup>

- 일반적인 edge-coverage 인스턴스를 병렬로 실행하세요. 추가 큐/맵 비용으로 초당 실행 횟수가 크게 줄어들지 않을 때만 더 풍부한 피드백이 유용합니다.
- 대규모 템플릿 중심 라이브러리나 일반 유틸리티 코드가 맵의 대부분을 차지한다면 `AFL_LLVM_ALLOWLIST`를 사용해 경로/호출자 계측을 제한하세요.
- 비순환 경로가 지나치게 많은 함수는 AFL++에서 건너뛸 수 있습니다. 컴파일 중 경고가 표시되면 대상에 allowlist를 적용하거나 엄격도를 낮춰야 한다는 신호입니다.
- 호출자 + 경로 커버리지는 호출자 깊이를 하나만 지원합니다. 더 깊은 컨텍스트 스택과 함께 사용하지 마세요.
- 경로 ID는 LLVM 메이저 버전 간에 달라질 수 있습니다. 캠페인 동안 툴체인을 고정하고, 빌드마다 기능 ID가 안정적인 것처럼 PATH 기반 코퍼스를 동기화하지 마세요.
- 이 피드백은 `CMPLOG`를 보완합니다. 비교 추적은 **가드에 어떤 값이 통과하는지**를 찾고, 경로/호출자 피드백은 **어떤 경로와 분기 조합이 해당 지점에 도달했는지**를 보존합니다.

## 상태 기반 Fuzzing: 시퀀스가 시드

**프로토콜**, **인증된 워크플로**, **다단계 파서**에서는 흥미로운 단위가 단일 blob이 아니라 **메시지 시퀀스**인 경우가 많습니다. 전체 대화를 하나의 파일로 이어 붙인 뒤 무작정 변형하는 방식은 대체로 비효율적입니다. 취약한 상태에 도달하는 메시지가 뒤쪽에 하나뿐이어도 fuzzer가 모든 단계를 똑같이 변형하기 때문입니다.<sup>[[4]](#references)</sup>

더 효과적인 방식은 **시퀀스 자체를 시드로 취급**하고, **관찰 가능한 상태**(응답 코드, 프로토콜 상태, 파서 단계, 반환된 객체 유형)를 추가 피드백으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **유효한 접두 메시지**는 그대로 유지하고 **상태 전이를 유도하는** 메시지에 변형을 집중하세요.
- 다음 단계가 이전 응답에 의존한다면, 식별자와 서버 생성 값을 캐시하세요.
- 직렬화된 전체 대화를 불투명한 blob처럼 변형하기보다 메시지별 변형/스플라이싱을 사용하세요.
- 프로토콜에서 의미 있는 응답 코드를 제공한다면, 이를 **저비용 상태 오라클**로 사용해 더 깊이 진행되는 시퀀스의 우선순위를 높이세요.

이것이 인증 관련 버그, 숨겨진 상태 전이 또는 “핸드셰이크 후에만 발생하는” 파서 버그가 일반적인 파일 방식 fuzzing에서 자주 발견되지 않는 이유이기도 합니다. fuzzer는 구조뿐 아니라 **순서, 상태, 종속성**도 보존해야 합니다.<sup>[[4]](#references)</sup>

### Android Binder: 멀티 클라이언트 드라이버 fuzzing

edge coverage가 높아도 IPC 드라이버 버그를 놓칠 수 있습니다. 커버리지는 **객체 소유권, 참조 횟수, 대기 중인 메시지, 정리 순서 또는 스레드 인터리빙**을 나타내지 않기 때문입니다. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 페이지에서는 드라이버 객체 모델을 다루며, 이 예제에서는 fuzzer 하네스에 초점을 맞춥니다. Android Binder는 유용한 모델입니다. 여러 프로세스가 필요한 순서로 같은 커널 객체를 다루도록 fuzzer를 만들 수 없다면, 할당 경로와 해제 경로를 모두 실행하는 것만으로는 충분하지 않습니다.<sup>[[15]](#references)</sup>

#### 개별 `ioctl` 버퍼가 아니라 프로토콜을 모델링하기

테스트 케이스는 **클라이언트 식별자 + 연산 + 구조화된 인수**로 구성된 순서 있는 문법으로 표현하세요. Binder LKL fuzzer는 protobuf와 `libprotobuf-mutator`를 사용하며, 영구적인 컨텍스트 매니저 클라이언트 하나와 일반 클라이언트 두 개를 둡니다. 그러면 의미를 반영하는 하네스가 무작위 바이트 변형으로 깨질 수 있는 관계를 보존합니다.<sup>[[15]](#references)</sup>

- 이전 연산이 반환한 값을 캐시하세요. 예를 들어 `BC_FREE_BUFFER`는 이전 `ioctl`이 반환한 트랜잭션 버퍼 포인터를 재사용해야 합니다.
- 동기 트랜잭션을 완료하고 이후 연산에 도달할 수 있도록 유효한 기본 응답을 생성하세요.
- 자기 자신에 대한 트랜잭션이나 동일한 대상으로 향하는 여러 대기 중 트랜잭션처럼 불가능한 상태 전이는 거부하세요.
- 싱글톤 부트스트랩 상태는 입력별 초기화 범위 밖에 두세요. Binder는 부팅당 `BINDER_SET_CONTEXT_MGR` 등록을 하나만 허용하므로, 해당 클라이언트를 반복해서 제거하고 재생성하면 이후 입력이 유효하지 않게 됩니다.

유용한 수명 경쟁 조건 템플릿은 한 클라이언트가 객체를 전달하게 하고, 스레드 또는 프로세스 정리를 시작한 뒤, 수신 클라이언트가 트랜잭션 버퍼를 해제하도록 동시에 실행하는 것입니다. CVE-2020-0423 사례에서는 `BINDER_TYPE_WEAK_BINDER` 전달 후 `BINDER_THREAD_EXIT`와 `BC_FREE_BUFFER`가 경쟁하면서, 종료 중인 스레드의 정리 경로가 계속 사용 중인 내장 `binder_work`가 해제될 수 있었습니다.<sup>[[15]](#references)</sup>

#### userspace 커널에서 제어된 인터리빙 재도입하기

[Linux Kernel Library (LKL)](https://github.com/lkl/linux)는 실제 커널 코드를 userspace 하네스에 링크하고 `lkl_syscall`을 통해 syscall 인터페이스를 제공합니다. 덕분에 한 프로세스에서 protobuf 상태, 커버리지, KASAN을 쉽게 조정할 수 있습니다. 하지만 LKL은 일반적으로 다른 커널 스레드가 끼어들지 않은 상태로 syscall을 실행합니다. 경쟁 조건 캠페인에서는 선택한 잠금/잠금 해제 및 수명 경계 주변에 `schedule()` 지점을 삽입한 뒤, 각 양보 지점에서 다음 클라이언트를 하네스가 무작위로 선택하도록 하세요. 각 지점은 스케줄링 검색 공간을 배가하므로 필요한 곳에만 제한적으로 두세요. 연구자들이 설명한 무작위 스케줄러는 upstream Binder fuzzer에 포함되어 **있지 않습니다**.<sup>[[15]](#references)</sup>

#### 직렬화된 회귀 시드 빌드 및 재생하기

upstream 하네스는 호환되는 `libprotobuf-mutator` 버전을 고정하고, `LKL_FUZZING=1`로 LKL fuzzing 계측과 KASAN을 활성화하며, `MMU=1`로 Binder용 `CONFIG_MMU`를 활성화합니다.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

의도적으로 취약한 리비전을 체크아웃하거나 업스트림에 문서화된 롤백 패치를 적용한 뒤에는, 직렬화된 시드만으로도 임시 C proof of concept에서 상태를 재구성하지 않고 전체 멀티클라이언트 상태 전이를 재현할 수 있습니다:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

결과적으로 발생한 KASAN use-after-free는 seed가 취약한 수명 경로에 도달했음을 확인해 줍니다. 이는 커널 코드 실행이나 권한 상승에 필요한 후속 primitive를 입증하지는 않습니다.<sup>[[16]](#references)</sup>

## 단일 머신 다양성 트릭 (Jackalope 스타일)

**생성형 신규성**과 **coverage 재사용**을 결합하는 실용적인 방법은 지속 실행 서버를 대상으로 짧은 수명의 worker를 **재시작**하는 것입니다. 각 worker는 빈 corpus에서 시작해 `T`초 후 동기화하고, 결합된 corpus를 사용해 다시 `T`초 동안 실행한 뒤, 다시 동기화하고 종료합니다. 이렇게 하면 누적된 coverage를 활용하면서도 **각 세대마다 새로운 구조**를 얻을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**서버:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**순차 작업자(루프 예시):**

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

- `-in empty`는 매 세대마다 **새 corpus**를 사용하도록 합니다.
- `-server_update_interval T`는 **지연된 동기화**(먼저 새로운 입력을 찾고, 나중에 재사용)를 구현합니다.
- grammar fuzzing 모드에서는 기본적으로 **초기 서버 동기화를 건너뜁니다**(`-skip_initial_server_sync`는 필요하지 않음).
- 최적의 `T`는 **대상에 따라 다릅니다**. worker가 대부분의 “쉬운” coverage를 찾은 뒤 전환하는 방식이 대체로 가장 효과적입니다.

## 다루기 어려운 대상의 Snapshot Fuzzing

테스트하려는 코드에 도달하려면 **많은 초기 설정 작업**(VM 부팅, 로그인 완료, 패킷 수신, 컨테이너 파싱, 서비스 초기화 등)이 필요한 경우, 유용한 대안은 **snapshot fuzzing**입니다. 준비된 프로세스나 VM 상태를 캡처하고, 각 테스트 케이스를 대상 입력 경로에 주입한 뒤, crash/timeout이 발생할 때까지 실행하고 snapshot을 복원합니다. 이렇게 하면 초기화나 프로토콜 접두부를 반복할 필요가 없으며, **네트워크 서비스**, **firmware**, **인증 후 공격 표면**, **binary-only 대상**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 흥미로운 상태가 준비될 때까지 대상을 실행합니다.
2. 해당 시점의 **메모리 + 레지스터**를 snapshot으로 저장합니다.
3. 각 테스트 케이스에서 변형된 입력을 관련 guest/process 버퍼에 직접 씁니다.
4. crash/timeout/reset이 발생할 때까지 실행합니다.
5. snapshot을 복원합니다. VM 대상의 경우 지원된다면 **변경된 페이지**만 복원한 뒤 반복합니다.

`recv`/`read` 또는 패킷 역직렬화 지점 이후처럼, 가능한 한 첫 번째 비용이 큰 파싱/디스패치 단계에 가까운 곳에 snapshot을 배치하고 대상이 사용하는 입력 버퍼를 기록합니다. 이는 입력 처리 과정에서 더 깊은 곳으로 snapshot을 옮겨 반복 작업을 피하는 적응형 배치 원칙을 따릅니다.<sup>[[11]](#references)</sup>

## MAccConc를 사용한 Linux 커널 Race 탐색

[MAccConc](https://github.com/googleprojectzero/MAccConc)는 타이밍에 민감한 Linux 커널 race를 재현 가능한 메모리 접근 스케줄로 변환합니다. 두 context의 **A-B-A** 실행을 자동으로 열거하거나, 분석가가 터미널 UI/GUI에서 순서 제약을 지정할 수 있습니다. 이는 완전한 concurrency fuzzer가 아니라 실험 단계의 연구 도구입니다. 현재 LLVM 23+와 프로젝트에서 패치한 커널이 필요하고, 명령줄 도구는 두 개의 테스트 스레드를 지원하며, 제안된 userspace fuzzing 계층은 구현되지 않았습니다.<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context 통신 지점 수집

KASAN outline callback과 패치된 KCOV 메모리 기록 지원을 포함해 계측된 커널을 빌드합니다. 프로젝트 README에서는 호출 스택을 계속 활용할 수 있도록 sibling-call 최적화도 비활성화할 것을 권장합니다.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`)는 instrumented access를 helper call로 변환합니다. MAccConc kernel patch는 연속된 access가 병합되지 않도록 `asan-opt-same-temp`를 비활성화합니다. 전역 변수 race도 확인해야 한다면 `asan-opt-globals` 최적화도 비활성화하세요. KCOV는 그 결과 생성된 레코드를 userspace로 전달합니다. 서로 다른 execution context에서 발생한 access를 비교하고, 바이트 범위가 겹치며 적어도 한쪽에서 write가 발생한 pair를 추립니다. `kfree()`도 write로 모델링하면 lifetime transition도 후보가 됩니다.<sup>[[17]](#references)</sup>

packet processing이나 RCU callback처럼 시작한 task의 범위를 벗어나는 작업의 경우, 해당 subsystem이 KCOV remote-coverage handle을 전달해야 합니다. Upstream remote KCOV는 opt-in 방식이며 임의의 background work에서 자동으로 사용할 수 없으므로, 전달이 누락되면 실제 상호작용이 보이지 않을 수 있습니다.<sup>[[17]](#references)[[19]](#references)</sup>

### 매 실행에서 동일한 동적 access 식별하기

할당 후 주소가 달라질 수 있는 구체적인 heap address로 재현하거나, `memcpy()`와 `spin_lock()` 같은 helper 내부에서 모호해지는 instruction address만 사용하는 것은 피하세요. MAccConc는 **count-augmented stack trace**를 사용합니다. 각 frame은 callee와 해당 caller 내 invocation count를 식별하며, 마지막 요소는 memory-access instruction을 식별합니다. SanitizerCoverage function-entry/exit record를 사용하면 userspace가 이 동적 식별자를 재구성할 수 있습니다. 이 식별자는 주소 변경 및 관련 없는 control-flow 변동에도 안정적으로 유지됩니다.<sup>[[17]](#references)</sup>

### 후보 pair를 강제 schedule로 변환하기

패치된 `KCOV_SET_DI` ioctl은 count-augmented access identifier를 shared-flag action과 연결합니다.<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 선택한 access 직전에 flag *N*을 설정합니다. |
| `DI_STACK_WAIT` | 선택한 access 직전에 flag *N*이 설정될 때까지 또는 설정된 제한 시간이 만료될 때까지 spin합니다. |
| `DI_STACK_WAKE_POST` | 선택한 access 직후에 flag *N*을 설정합니다. |

부분적인 **A-happens-before-B** 제약을 적용하려면 A에는 `DI_STACK_WAKE_POST`를, B에는 같은 flag를 사용하는 `DI_STACK_WAIT`를 설정합니다. 두 context의 schedule을 완전히 지정하려면 B를 blocked 상태로 시작한 다음, A가 B를 깨우고 첫 transfer 지점에서 대기하도록 합니다. 다음 transfer에서는 B가 반대 작업을 수행합니다. 이 방식은 deterministic context switching처럼 동작하며, 자동 A-B-A explorer가 사용합니다.<sup>[[17]](#references)</sup>

최소한의 campaign에서는 네 개의 hook(`test_setup`, 두 thread function, `test_end`)으로 구성된 test case를 shared library로 컴파일하고, 제약 없는 trace를 수집한 뒤 A-B-A 후보를 열거하거나 의심스러운 access 주변에 수동 제약을 추가합니다.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

타임아웃은 성공적인 순서 재배치와 별도로 해석하세요. lock 또는 초기화/게시 의존성 때문에 두 번째 context가 injection 지점에 도달하지 못해 요청한 순서가 불가능할 수 있습니다. 또한 KASAN의 사각지대도 염두에 두세요. 직접적인 stack 접근은 범위를 벗어날 가능성이 없는 한 일반적으로 후킹되지 않고, 기본 최적화에서는 전역 변수가 제외되며, 현재 컴파일러는 ASAN과 TSAN 후크를 동시에 생성할 수 없습니다. 마지막으로, 프로토타입은 guest가 panic을 일으키면 KCOV 버퍼를 잃으므로 별도의 crash console/oracle을 유지하세요.<sup>[[17]](#references)</sup>

향후 concurrency-guided fuzzing을 위해 입력 또는 syscall별 메모리 접근 요약을 기록하고, context 간 통신 지점을 형성할 수 있는 연산들을 짝지은 다음 해당 조합만 탐색하세요. VM snapshot은 전역 상태와 주소를 안정화합니다. snapshot이 없다면 allocation-site 메타데이터를 사용해 실행 간 객체를 추상화할 수 있습니다. 이는 제안된 확장 기능이지, 현재 MAccConc userspace 도구의 기능은 아닙니다.<sup>[[17]](#references)</sup>

## Harness 인트로스펙션: 얕은 fuzzer를 조기에 찾기

campaign이 정체되면 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **도달 가능성/coverage 인트로스펙션**을 사용해 fuzz target에서 정적으로는 도달 가능하지만 동적으로는 거의 또는 전혀 coverage되지 않는 함수를 찾아보세요. 이런 함수는 대개 다음 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- harness가 target에 너무 늦게 또는 너무 일찍 진입합니다.
- seed corpus에 기능군 전체가 빠져 있습니다.
- target에는 하나의 과도하게 큰 “모든 작업을 처리하는” harness 대신 **두 번째 harness**가 실제로 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일의 워크플로를 사용한다면, Fuzz Introspector를 통해 정적 도달 가능성과 runtime coverage를 비교하고 시간 제한 실행 또는 공개 corpus에서 보고서를 생성할 수 있습니다.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

보고서를 바탕으로 테스트되지 않은 parser 경로에 새 harness를 추가할지, 특정 기능의 corpus를 확장할지, 아니면 하나로 뭉쳐 있는 harness를 더 작은 진입점으로 나눌지 결정하세요.

## 그래프 우선 fuzz 타깃 선정 및 mutation 분류

이미 **정적 분석 결과**, **mutation testing에서 살아남은 항목**, **coverage 보고서**가 있다면, 이를 서로 독립된 목록으로 분류하지 마세요. 먼저 **호출 그래프**를 만들고, 노드에 **순환 복잡도**, **진입점/비신뢰 입력 도달 가능성**, 외부 분석 결과를 표시한 다음 그래프에 관한 질문을 살펴보세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 복잡도가 높은 함수 중 비신뢰 입력에서 도달할 수 있는 함수는 무엇인가요?
- parser/handler에서 보안상 중요한 코드로 이어지는 경로에 있는 mutation survivor는 무엇인가요?
- **blast radius**가 유난히 큰 아키텍처상의 병목 지점은 어떤 함수인가요?

이 방법을 사용하면 보통 단순히 "coverage가 가장 낮은 곳"을 고르는 것보다 더 나은 fuzz 타깃을 찾을 수 있습니다. **복잡도가 높고** 외부에서 접근할 수 있음이 확인된 parser/decoder는 공격자가 제어할 수 있는 경로가 없는, coverage가 낮은 내부 helper보다 더 적합한 harness 대상입니다.

### 실용적인 분류 워크플로

1. 코드베이스에서 **코드 그래프**를 만들고 함수별 복잡도/분기 지표를 추출합니다.
2. 공격자가 제어하는 입력을 받는 **진입점**을 열거합니다. 예: request handler, decoder, importer, protocol parser, CLI/file reader.
3. 해당 진입점에서 후보 함수까지 **경로 쿼리**를 실행해, 도달 가능한 공격 표면과 비활성/내부 전용 코드를 구분합니다.
4. 다음 조건을 결합하는 노드를 우선순위에 둡니다.
   - 높은 **순환 복잡도**
   - 비신뢰 입력에서 도달 가능함이 확인됨
   - 높은 **blast radius** 또는 다수의 하위 의존성
   - **SARIF** 분석 결과, audit 메모, mutation survivor 등 이를 뒷받침하는 근거
5. 점수가 가장 높은 노드부터 집중형 harness를 작성합니다. 특히 hex/Base64/IP/message decoder 같은 **parser/codec**을 우선합니다.

### Mutation survivor: 동등한 항목과 조치가 필요한 항목

Mutation testing은 survivor 목록에 노이즈를 많이 포함하는 경우가 많습니다. 모든 survivor를 보안 결함으로 간주하기 전에, 그래프를 사용해 다음을 확인하세요.

- 변이된 함수에 공격자가 제어하는 진입점에서 도달할 수 있나요?
- 모든 호출 경로에서 변이된 검증보다 더 강한 불변 조건이 적용되나요?
- 해당 노드는 비활성 코드, 형식 지정 전용 로직, 영향이 큰 산술/파서 경로 중 어디에 있나요?

도달할 수 없거나 구조적으로 제약된 survivor는 대개 **동등 변이**입니다. 계속 **도달 가능**하며 **경계 조건**, **overflow/carry 경로**, 또는 **보안상 중요한 산술/파싱**에 영향을 주는 survivor는 다음 항목으로 승격해야 합니다.

- 새 fuzz harness
- 직접적인 속성/불변 조건 테스트
- 표적화된 edge-case 벡터

### 외부 분석 결과를 그래프에 매핑

SAST 파이프라인에서 **SARIF**를 내보낸다면, **파일 + 줄 범위**를 기준으로 분석 결과를 그래프 노드에 매핑하고 그래프를 사용해 영향 범위를 확장하세요.<sup>[[6]](#references)</sup>

- 표시된 함수의 **blast radius**를 계산합니다.
- 해당 분석 결과가 진입점에서 이어지는 경로에 있는지 확인합니다.
- 인접한 분석 결과 중 같은 병목 지점으로 모이는 항목을 그룹화합니다.

이 방법은 특정 함수에 fuzzing 시간을 투자할지 판단할 때 유용합니다. **도달 가능하고**, **복잡하며**, 이미 **SAST 결과가 있는** 노드는 공격자 경로가 없는 단순 복잡 노드보다 더 나은 타깃인 경우가 많습니다.

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

중요한 방법론은 **복잡도 x 노출도 x 영향도**의 교차점입니다. 그래프를 활용해 기대 보안 가치가 가장 높은 fuzz 대상들을 선택한 다음, mutation을 통과한 입력을 바탕으로 harness에서 어떤 경계와 불변 조건을 집중적으로 테스트해야 할지 결정하세요.<sup>[[5]](#references)</sup>

## gosentry를 이용한 Go Fuzzing: 더 강력한 엔진, 타입이 지정된 입력, 차등 검사

Go 대상에 이미 네이티브 `testing.F` harness가 있다면, 실용적인 업그레이드 방법은 동일한 harness를 [gosentry](https://github.com/trailofbits/gosentry)와 함께 실행하는 것입니다. gosentry는 `go test -fuzz`를 유지하면서 백엔드를 **LibAFL**로 교체한 Go toolchain 포크입니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

네이티브 Go fuzzer가 **어려운 비교**, **타입이 지정된 입력**, **파서 중심 형식**에서 정체될 때 유용합니다. 방법론은 동일합니다.

- 시드에는 `f.Add(...)`를, 콜백에는 `f.Fuzz(...)`를 계속 사용합니다.
- 동일한 harness를 재사용하되, 기본 toolchain 대신 gosentry의 `go` 바이너리로 실행합니다.
- 결과 캠페인을 일반적인 coverage-guided 실행으로 취급하되, LibAFL의 스케줄링/변이와 더 나은 주변 detector를 활용합니다.

### 조용한 실패를 퍼징 결과로 전환하기

Go 평가에서 반복적으로 나타나는 문제는 위험한 동작이 기본 설정에서는 **crash를 일으키지 않는 경우가 많다**는 점입니다. gosentry를 사용하면 여러 종류의 “나쁘지만 조용한” 상태를 결과로 전환할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용해 선택한 logging/error 경로가 crash처럼 동작하게 합니다. 그렇지 않으면 로그만 남기고 계속 실행하는 `log.Fatal` 스타일의 코드 경로에 유용합니다.
- `--catch-races=true`를 사용해 새로 발견된 queue 항목을 Go race detector로 다시 실행합니다.
- `--catch-leaks=true`를 사용해 새 queue 항목을 `goleak`으로 다시 실행하고 goroutine leak이 발생하면 중단합니다.
- LibAFL의 hang 처리를 통해 **무한 루프/매우 느린 입력**이 timeout으로 사라지지 않고 퍼징 결과로 남도록 합니다.
- 기본적으로 내장된 arithmetic overflow 검사와, go-panikint 스타일의 instrumentation을 통한 선택적 truncation 검사를 제공합니다.

이는 보안 영향이 memory corruption이 아니라 **panic을 일으키지 않는 파서 실패**, **동시성 버그**, 또는 **DoS만 유발하는 hang**인 대상에 특히 유용합니다.

### 타입이 지정된 Go API를 위한 구조체 인식 퍼징

네이티브 Go fuzzing은 주로 `[]byte`, `string`, 숫자 같은 스칼라를 예상합니다. 테스트 대상 코드가 타입이 지정된 객체를 사용한다면, gosentry는 내부적으로 바이트를 계속 변이하면서 **복합 값**(struct, slice, array, pointer)을 직접 퍼징할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing만을 위해 가짜 wire format을 만들면 harness 전용 파싱 코드 뒤에 로직 버그가 숨겨질 수 있습니다. differential 또는 grammar-based 캠페인의 경우 harness 입력을 단일 `[]byte` 또는 `string`으로 유지하고 대신 callback 내부에서 파싱하세요.

### 파서 및 프로토콜 입력을 위한 Grammar-based fuzzing

파서, 형식 및 입력 언어의 경우 gosentry는 LibAFL 기반으로 **Nautilus grammar fuzzing**을 실행할 수 있습니다. grammar는 production rule의 JSON 배열이며, harness는 일반적으로 단일 `[]byte` 또는 `string` 인수를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

방법론 참고 사항:

- 바이트 수준 변형이 대부분 초기 구문 검사에서 차단된다면 grammar mode를 사용합니다.
- 문법은 언어/프로토콜의 전체 사양이 아니라 **보안 관련 하위 집합**에 초점을 맞춥니다.
- 정수, 길이, 상태 머신의 경계 사례를 자극할 수 있도록 terminal/nonterminal에 큰 경계값을 사용합니다.
- grammar mode는 입력을 문법에 맞게 유지하지만, 대상은 여전히 **바이트/문자열**을 받으므로 파싱 및 의미 검사는 하네스가 적용된 코드 내부에서 수행됩니다.

### Differential fuzzing: 충돌뿐 아니라 구현을 비교합니다

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

다음과 같은 경우를 발견 사항으로 간주하세요.

- 한 구현은 panic이 발생하지만 다른 구현은 정상적으로 거부함
- 입력의 수락/거부 결과가 일치하지 않음
- 파스 트리 또는 디코딩된 객체가 다름
- 상태 전이, nonce, 잔액 또는 상태 루트가 서로 다름

이는 순수한 crash fuzzing으로는 놓치기 쉬운 **합의 불일치**, **파서 모호성**, **명세와 구현 간 차이**를 찾는 실용적인 방법입니다.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 커버리지 보고를 위해 캠페인 코퍼스 재사용

캠페인이 끝난 뒤 저장된 큐 코퍼스를 재생해, 별도의 코퍼스를 수동으로 내보내지 않고도 Go 커버리지 보고서를 생성할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

같은 package에서 동일한 `-fuzz` target으로 명령을 실행해야 gosentry가 올바른 캐시된 campaign state를 확인합니다.



## References

- [1] [변이 문법 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing 심층 분석](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [5년 후의 AFLNet: 커버리지 기반 프로토콜 fuzzing에 관하여](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark가 코드를 그래프로 변환하는 방법](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing에는 도구의 절반이 빠져 있었습니다. 이를 해결하기 위해 toolchain을 fork했습니다.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 스냅샷을 사용하는 상태 저장 네트워크 프로토콜용 고속 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [문법이 없어도 문제없다: 시스템 호출 설명 없이 Linux 커널을 fuzzing하는 방법](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: 적응형 및 변경 가능한 스냅샷을 이용한 효율적인 fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: 경로 및 caller 커버리지](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [예측형 컨텍스트 민감 fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 빌드 및 회귀 시드 문서](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: 메모리 접근 순서를 제어해 Linux 커널 경쟁 조건 탐색하기](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing을 위한 코드 커버리지](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 확장 파일 이름 구문](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 보안 권고: CFITSIO 2025년 4분기](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO 확장 파일 이름 구문 fuzzing: 16개의 메모리 안전성 취약점 및 Codex 지원 분류](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
