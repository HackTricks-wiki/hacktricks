# 퍼징 방법론

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: 커버리지와 의미론

**Mutational Grammar Fuzzing**에서는 입력을 **문법적으로 유효한 상태로 유지하면서** 변이합니다. 커버리지 기반 모드에서는 **새로운 커버리지**를 유발한 샘플만 코퍼스 시드로 저장합니다. **언어 대상**(파서, 인터프리터, 엔진)의 경우, 한 구문의 출력이 다른 구문의 입력이 되는 **의미론적/데이터 흐름 체인**이 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**실패 양상:** 퍼저가 각각 `document()`와 `generate-id()`(또는 유사한 기본 요소)를 실행하는 시드는 찾지만, **연결된 데이터 흐름을 보존하지 못해** 버그에 더 가까운 샘플이 커버리지를 늘리지 않는다는 이유로 버려집니다. 서로 의존하는 단계가 **3개 이상**이면 무작위 재조합에 많은 비용이 들고, 커버리지 피드백도 탐색 방향을 제시하지 못합니다.<sup>[[1]](#references)</sup>

**시사점:** 의존성이 많은 문법에서는 **변이 단계와 생성 단계를 결합**하거나, 커버리지만이 아니라 **함수 체이닝** 패턴을 우선 생성하도록 편향을 줄 수 있습니다.<sup>[[1]](#references)</sup>

## 코퍼스 다양성의 함정

커버리지 기반 변이는 **탐욕적**입니다. 새로운 커버리지를 내는 샘플은 대개 변경되지 않은 큰 영역을 그대로 유지한 채 즉시 저장됩니다. 시간이 지나면 코퍼스에 구조적 다양성이 낮은 **거의 중복된 샘플**이 쌓입니다. 지나치게 공격적인 최소화는 유용한 맥락을 제거할 수 있으므로, 실용적인 절충안은 **최소 토큰 임계값에서 멈추는 문법 인식형 최소화**입니다. 이렇게 하면 노이즈를 줄이면서도 변이에 적합한 주변 구조를 충분히 유지할 수 있습니다.<sup>[[1]](#references)</sup>

변이 기반 퍼징에서 실용적인 코퍼스 원칙은 다음과 같습니다. 많은 수의 거의 중복된 샘플보다 **구조적으로 서로 다른 소수의 시드로 커버리지를 최대화**하는 편이 낫습니다. 실제로는 보통 다음을 의미합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **실제 샘플**(공개 코퍼스, 크롤링 데이터, 캡처한 트래픽, 대상 생태계의 파일 모음)에서 시작합니다.
- 유효한 샘플을 모두 보관하는 대신 **커버리지 기반 코퍼스 최소화**로 샘플을 추립니다.
- 변이가 대부분 무관한 바이트에 소모되지 않고 의미 있는 필드에 적용되도록 시드 크기를 **충분히 작게** 유지합니다.
- 하네스나 계측을 크게 변경한 뒤에는 코퍼스 최소화를 다시 실행합니다. 도달 가능성이 바뀌면 “최적의” 코퍼스도 달라지기 때문입니다.

## 대규모 생성 프로그램과 타임아웃 편향

컴파일러 및 인터프리터 퍼징에서는 입력이 새로운 파서 분기를 통과하는 대신 **생성 코드 크기 임계값**을 넘어야 할 수 있습니다. V8의 [예외 핸들러 오프셋 예시](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size)에서는 잘린 핸들러 오프셋이 영향을 미치기 전에 유효한 테스트 케이스가 256 MiB가 넘는 바이트코드를 필요로 했습니다. `yield*` 구문을 반복하면 해당 경계에 도달할 수 있었지만, 디버그 빌드에서 테스트 케이스를 컴파일하는 데 몇 초가 걸렸습니다. 작은 입력을 선호하거나 실행 타임아웃을 짧게 설정하면 문법 커버리지가 높더라도 이런 유형의 테스트가 불리해질 수 있습니다. 패킹된 오프셋이나 길이에 민감한 기타 메타데이터를 감사할 때는 크기 임계값과 타임아웃 정책을 별도로 고려하세요. 이 캠페인 관련 조언은 보고된 실패 양상에서 추론한 것입니다.<sup>[[29]](#references)</sup>

## 매직 값에 대한 비교 인식 변이

퍼저가 정체되는 흔한 원인은 문법이 아니라 **엄격한 비교**입니다. 매직 바이트, 길이 검사, 열거형 문자열, 체크섬 또는 파서 디스패치 값이 `memcmp`, 스위치 테이블, 연쇄 비교로 검사되는 경우가 이에 해당합니다. 순수 무작위 변이는 이러한 값을 바이트 단위로 추측하는 데 사이클을 낭비합니다.

이런 대상에는 **비교 추적**(예: AFL++ `CMPLOG` / Redqueen 방식 워크플로)을 사용하세요. 퍼저가 실패한 비교의 피연산자를 관찰하고, 비교를 통과하는 값에 맞춰 변이를 유도할 수 있습니다.<sup>[[3]](#references)</sup>

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

**실전 참고 사항:**

- 대상이 **파일 시그니처**, **프로토콜 동사**, **타입 태그** 또는 **버전에 따라 달라지는 기능 비트** 뒤에 심층 로직을 숨기는 경우 특히 유용합니다.
- 실제 샘플, 프로토콜 사양 또는 디버그 로그에서 추출한 **사전**과 함께 사용하세요. 문법 토큰, 청크 이름, 동사, 구분 기호가 포함된 작은 사전이 방대한 범용 단어 목록보다 더 유용한 경우가 많습니다.
- 대상이 순차적으로 여러 검사를 수행한다면, 가장 먼저 나오는 “매직” 비교부터 해결한 다음 결과 코퍼스를 다시 최소화하여 이후 단계가 이미 유효한 접두사부터 시작하도록 하세요.

## 파일명 언어를 숨기는 파일 API Fuzzing

`filename`, `path` 또는 `URL`이라는 매개변수는 단순한 파일 조회가 아니라 인터프리터 진입점일 수 있습니다. 예를 들어 CFITSIO Extended Filename Syntax (EFS)는 대괄호로 묶인 선택자, 행/픽셀 표현식, 계산된 열, 히스토그램 및 변환을 평가한 뒤 열린 객체를 반환하며, 일부 형식은 임시 복사본도 생성합니다. 공격 표면을 매핑하는 동안 각 open/import API를 **리터럴 경로** 또는 **해석된 경로**로 분류하고, 애플리케이션이 실제로 호출하는 프로덕션 진입점을 fuzz하세요.<sup>[[20]](#references)[[22]](#references)</sup>

그 결과로 얻을 수 있는 SSRF, 파일 복사 및 프로토콜 핸들러 프리미티브와 더 안전한 리터럴 경로 API는 [SSRF/파일 프리미티브로서의 파일명 미니 언어](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)를 참고하세요.<sup>[[20]](#references)</sup>

### 백업 객체와 fuzz 대상 프로그램을 분리하기

문법이 파일명 접미사에 있을 때 참조된 파일 바이트만 변형하면 파서를 놓치게 됩니다. 대신 간단한 하네스가 테스트케이스를 문자열로 읽어 해석된 open API에 전달하도록 할 수 있습니다. CFITSIO 캠페인에서는 `fits_open_file()`을 읽기 전용 모드로 호출해 대부분의 EFS 파서와 평가기에 도달했습니다. 유효한 백업 파일은 별도로 유지하여, 기본 경로를 계속 망가뜨리는 대신 선택자/표현식 언어에 변형을 집중할 수 있도록 하세요.<sup>[[22]](#references)</sup>

각각 다른 문법 계열에 도달하는 시드를 사용한 다음, 사양과 lexer/parser 소스 양쪽에서 간결한 사전을 만드세요. 입력이 반복적으로 같은 구문 오류 경로에서 실패해 커버리지가 정체되면, 유효한 접두사를 보존하고 무작위 변형 시간을 늘리는 대신 구분 기호, 연산자, 키워드, 함수 이름 및 대표 필드 이름을 추가하세요.<sup>[[22]](#references)</sup>

예를 들어 문법 사전을 사용해 하네스를 실행하세요:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness 부작용 제한

라이브러리의 read-only 플래그만으로 테스트케이스에 부작용이 없다고 보장할 수는 없습니다. filename 언어가 입력을 다시 쓰거나, 출력 파일을 만들거나, 임시 객체를 구체화할 수 있습니다. CFITSIO 캠페인에서는 시드 파일이 처음에 파괴되고 파일시스템 곳곳에 예상치 못한 파일이 남았으므로 정리와 격리가 필요했습니다.<sup>[[22]](#references)</sup>

- 각 worker에 폐기 가능한 작업 디렉터리와 전용 임시 디렉터리를 제공합니다.
- 정식 backing 파일은 복사본으로 노출하고, 대상이 corpus의 유일한 사본을 변경하지 못하게 합니다.
- 원격 backend가 의도한 대상이 아니라면 네트워크 접근을 비활성화하고, 컨테이너, mount namespace 또는 이에 준하는 sandbox로 쓰기 가능한 경로를 제한합니다.
- 각 실행 또는 worker 배치 후 디렉터리를 초기화하고, 예상치 못한 파일시스템 변경도 추가 발견 사항으로 취급합니다.

### 크래시-패치-fuzz 반복 주기

수천 개의 artifact가 수천 개의 패치 작업으로 이어지지 않도록 복구 전에 크래시를 클러스터링합니다. CFITSIO 평가에서 AFLTriage는 초기 크래시 집합을 몇 가지 근본 원인으로 줄였습니다. 그 결과로 작성된 권고문에는 잘못된 대상 크기 검사, `realloc()` 이후의 오래된 포인터, 산술 오류, 안전하지 않은 parser 정리 경로 등 서로 다른 실패가 나타납니다.<sup>[[21]](#references)[[22]](#references)</sup>

1. 각 클러스터를 대표하는 입력을 최소화하고 AddressSanitizer로 재현합니다.
2. 실패한 접근, 소스 위치, 할당/해제 이력, 그리고 불변 조건을 깨뜨린 parser 상태를 정확히 기록합니다.
3. 범위를 좁힌 후보 패치를 하나 적용하고 동일한 coverage 및 sanitizer 계측으로 다시 빌드합니다.
4. 원래 재현 입력과 해당 클러스터의 **모든 입력**을 재실행합니다. 메모리 안전성 수정이 오류 경로의 소유권 처리를 깨뜨릴 수 있으므로 leak detection도 활성화합니다.
5. 실제 파일로 기능 테스트를 실행한 다음 누적된 queue에서 재개합니다. (엔진에서 바이너리 변경 후 새 output 디렉터리가 필요하다면 해당 queue를 다시 가져옵니다.)
6. 반복합니다. 첫 번째 얕은 크래시를 제거하면 기존 시드가 더 깊은 parser 상태까지 진행되는 경우가 많습니다.

크래시 입력, sanitizer 보고서, harness, 관련 소스 코드를 제공하면 LLM이 2단계를 빠르게 진행하고 3단계의 초안을 작성할 수 있지만, 패치는 여전히 신뢰할 수 없는 상태입니다. 수정 수락 여부는 모델의 설명이 아니라 sanitizer 재실행과 회귀 테스트 기준으로 판단해야 합니다.<sup>[[22]](#references)</sup>

## Edge Coverage로 구분되지 않는 경로에 더 풍부한 피드백 제공

일반적인 edge coverage로는 같은 helper를 서로 다른 caller를 통해 실행하거나 함수 내부에서 서로 다른 branch 조합을 택하는 두 실행을 구분할 수 없습니다. 이는 **경로**에 따라 활성 상태가 달라지는 공유 decoder, protocol dispatcher, interpreter helper에서 중요합니다. 모든 호출 문맥을 무작정 추적하는 것도 위험합니다. coverage map과 queue가 폭발적으로 커질 수 있기 때문입니다. 따라서 context-sensitive fuzzing 연구에서는 전체 call graph를 context-sensitive하게 처리하기보다, 유망한 문맥만 세분화할 것을 권장합니다.<sup>[[14]](#references)</sup>

최신 AFL++ 빌드에는 일반적인 edge coverage 외에 **함수별 Ball-Larus 경로 coverage**가 제공됩니다. 함수 내 각 비순환 경로에 feature를 할당합니다. loop back-edge는 제거되므로 이 피드백은 branch 조합은 구분하지만 **반복 횟수는 구분하지 않습니다**. 완화된 level `1`부터 시작한 뒤, 경로 수가 기하급수적으로 늘어날 수 있으므로 더 엄격한 모드는 의심스러운 parser/state-machine 코드에만 적용합니다.<sup>[[13]](#references)</sup>

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

**캠페인 가이드:** 더 풍부한 피드백은 신중하게 적용하고, coverage-map/queue 비용을 모니터링하세요.<sup>[[13]](#references)[[14]](#references)</sup>

- 일반 edge-coverage 인스턴스를 병렬로 실행하세요. 추가 queue/map 비용으로 초당 실행 횟수가 감소하지 않을 때만 더 풍부한 피드백이 유용합니다.
- 템플릿을 많이 사용하는 대형 라이브러리나 일반 유틸리티 코드가 map의 대부분을 차지한다면 `AFL_LLVM_ALLOWLIST`를 사용해 경로/호출자 계측 범위를 제한하세요.
- 비순환 경로가 지나치게 많은 함수는 AFL++에서 건너뛸 수 있습니다. 컴파일 중 경고가 나오면 대상에 allowlisting을 적용하거나 엄격도를 낮춰야 한다는 뜻입니다.
- 호출자 + 경로 커버리지는 호출자 깊이를 하나만 지원합니다. 더 깊은 컨텍스트 스택과 함께 사용하지 마세요.
- 경로 ID는 LLVM 메이저 버전에 따라 달라질 수 있습니다. 캠페인 동안 툴체인을 고정하고, 빌드마다 기능 ID가 안정적이라고 가정해 PATH 기반 코퍼스를 동기화하지 마세요.
- 이 피드백은 `CMPLOG`를 보완합니다. 비교 추적은 **가드를 통과하는 값이 무엇인지** 해결하고, 경로/호출자 피드백은 **어떤 경로와 분기 조합이 그 지점에 도달했는지** 보존합니다.

## Stateful Fuzzing: 시퀀스가 시드

**프로토콜**, **인증된 워크플로**, **다단계 파서**에서는 흥미로운 단위가 단일 blob이 아니라 **메시지 시퀀스**인 경우가 많습니다. 전체 대화를 하나의 파일로 연결해 무작정 변이하는 방식은 대개 비효율적입니다. 퍼저가 취약한 상태에 도달하는 후속 메시지에만 변이를 집중하지 않고 모든 단계를 똑같이 변이하기 때문입니다.<sup>[[4]](#references)</sup>

더 효과적인 방식은 **시퀀스 자체를 시드로** 취급하고, **관찰 가능한 상태**(응답 코드, 프로토콜 상태, 파서 단계, 반환된 객체 유형)를 추가 피드백으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **유효한 접두 메시지**는 그대로 유지하고, **상태 전이를 유도하는** 메시지에 변이를 집중하세요.
- 다음 단계가 이전 응답에 의존한다면, 식별자와 서버가 생성한 값을 캐시하세요.
- 직렬화된 대화 전체를 불투명한 blob으로 변이하기보다 메시지 단위 변이/스플라이싱을 사용하세요.
- 프로토콜이 의미 있는 응답 코드를 제공한다면, 이를 **저비용 상태 오라클**로 활용해 더 깊은 단계까지 진행하는 시퀀스의 우선순위를 높이세요.

인증이 필요한 버그, 숨겨진 상태 전이, 또는 “핸드셰이크 이후에만 발생하는” 파서 버그가 일반적인 파일 방식 fuzzing에서 자주 발견되지 않는 이유도 같습니다. 퍼저는 구조뿐 아니라 **순서, 상태, 종속성**을 보존해야 합니다.<sup>[[4]](#references)</sup>

### Android Binder: 멀티 클라이언트 드라이버 퍼징

높은 edge coverage를 달성해도 IPC 드라이버 버그를 놓칠 수 있습니다. 커버리지로는 **객체 소유권, 참조 횟수, 대기 중인 메시지, 정리 순서, 스레드 인터리빙**을 파악할 수 없기 때문입니다. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 페이지에서는 드라이버 객체 모델을 다룹니다. 이 예제에서는 퍼저 하네스에 초점을 맞춥니다. Android Binder는 유용한 모델입니다. 퍼저가 여러 프로세스에서 동일한 커널 객체를 필요한 순서대로 조작하지 못한다면, 할당 경로와 해제 경로에 모두 도달하는 것만으로는 충분하지 않습니다.<sup>[[15]](#references)</sup>

#### 분리된 `ioctl` 버퍼가 아니라 프로토콜을 모델링하세요

테스트 케이스를 **클라이언트 ID + 연산 + 구조화된 인수**로 이루어진 순서 있는 문법으로 표현하세요. Binder LKL 퍼저는 protobuf와 `libprotobuf-mutator`를 사용하며, 영구적인 context-manager 클라이언트 하나와 일반 클라이언트 두 개를 둡니다. 의미 기반 하네스는 무작위 바이트 변이로 파괴될 관계를 보존합니다.<sup>[[15]](#references)</sup>

- 이전 연산에서 반환된 값을 캐시하세요. 예를 들어 `BC_FREE_BUFFER`는 이전 `ioctl`이 반환한 트랜잭션 버퍼 포인터를 재사용해야 합니다.
- 유효한 기본 응답을 생성해 동기 트랜잭션이 완료되고 이후 연산에도 도달할 수 있게 하세요.
- 자기 자신에게 보내는 트랜잭션이나 동일한 대상에 대한 여러 대기 중 트랜잭션처럼 불가능한 상태 전이는 거부하세요.
- 싱글턴 부트스트랩 상태는 입력별 초기화 범위 밖에 두세요. Binder는 부팅당 `BINDER_SET_CONTEXT_MGR` 등록을 한 번만 허용하므로, 해당 클라이언트를 반복해서 폐기하고 다시 만들면 이후 입력이 유효하지 않게 됩니다.

유용한 수명 경쟁 조건 템플릿은 한 클라이언트가 객체를 전송하고 스레드 또는 프로세스 정리를 시작하게 한 뒤, 수신 클라이언트가 동시에 트랜잭션 버퍼를 해제하게 하는 것입니다. CVE-2020-0423 예제에서는 `BINDER_TYPE_WEAK_BINDER` 전송 후 `BINDER_THREAD_EXIT`와 `BC_FREE_BUFFER`가 경쟁하면, 종료 중인 스레드의 정리 경로가 아직 사용 중인 내장 `binder_work`가 해제될 수 있었습니다.<sup>[[15]](#references)</sup>

#### 사용자 공간 커널에서 제어된 인터리빙 재도입

[Linux Kernel Library (LKL)](https://github.com/lkl/linux)는 실제 커널 코드를 사용자 공간 하네스에 링크하고 `lkl_syscall`을 통해 syscall 인터페이스를 노출합니다. 따라서 한 프로세스에서 protobuf 상태, 커버리지, KASAN을 쉽게 조율할 수 있습니다. 하지만 LKL은 일반적으로 다른 커널 스레드가 syscall을 중단하지 않도록 실행합니다. 경쟁 조건 캠페인에서는 선택한 잠금/잠금 해제 및 수명 경계 주변에 `schedule()` 지점을 삽입한 다음, 각 yield 지점에서 다음 클라이언트를 하네스가 무작위로 선택하게 하세요. 각 지점은 스케줄링 탐색 공간을 확대하므로, 필요한 곳에만 제한적으로 추가하세요. 연구자들이 설명한 무작위 스케줄러는 upstream Binder 퍼저에 포함되어 있지 **않습니다**.<sup>[[15]](#references)</sup>

#### 직렬화된 회귀 시드 빌드 및 재생

upstream 하네스는 호환되는 `libprotobuf-mutator` 버전을 고정하고, `LKL_FUZZING=1`로 LKL 퍼징 계측과 KASAN을 활성화하며, `MMU=1`로 Binder의 `CONFIG_MMU`를 활성화합니다.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

의도적으로 취약한 리비전을 체크아웃하거나 upstream에 문서화된 롤백 패치를 적용하면, 직렬화된 시드로 임시 C PoC에서 상태를 직접 재구성하지 않고도 전체 다중 클라이언트 상태 전이를 재현할 수 있습니다:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

KASAN use-after-free가 발생했다면, 이는 seed가 취약한 객체 수명 경로에 도달했다는 확인으로 간주하세요. 이는 커널 코드 실행이나 권한 상승에 필요한 후속 primitive까지 입증하는 것은 **아닙니다**.<sup>[[16]](#references)</sup>

## 단일 머신 다양성 트릭 (Jackalope 스타일)

**생성형 신규성**과 **coverage 재사용**을 결합하는 실용적인 방법은 지속 실행되는 서버를 대상으로 짧은 수명의 worker를 **재시작**하는 것입니다. 각 worker는 빈 corpus에서 시작해 `T`초 후 동기화하고, 결합된 corpus로 다시 `T`초 동안 실행한 뒤, 다시 동기화하고 종료합니다. 이렇게 하면 누적된 coverage를 활용하면서도 **각 세대마다 새로운 구조**를 얻을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**순차 worker(루프 예시):**

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

- `-in empty`는 generation마다 **새 corpus**를 강제합니다.
- `-server_update_interval T`는 **지연된 sync**(먼저 novelty를 찾고 나중에 재사용)를 근사합니다.
- grammar fuzzing 모드에서는 기본적으로 **초기 server sync를 건너뜁니다**(`-skip_initial_server_sync`를 지정할 필요 없음).
- 최적의 `T`는 **target에 따라 다릅니다**. worker가 대부분의 “쉬운” coverage를 찾은 뒤 전환하는 방식이 대체로 가장 효과적입니다.

## 하네싱하기 어려운 타깃을 위한 Snapshot Fuzzing

테스트하려는 코드에 도달하려면 **큰 초기화 비용**(VM 부팅, 로그인 완료, 패킷 수신, 컨테이너 파싱, 서비스 초기화)이 드는 경우, 유용한 대안은 **snapshot fuzzing**입니다. 준비된 프로세스나 VM 상태를 캡처하고, 각 testcase를 target 입력 경로에 주입한 다음, crash/timeout이 발생할 때까지 실행하고 snapshot을 복원합니다. 이렇게 하면 초기화나 프로토콜 prefix를 반복할 필요가 없어 **network services**, **firmware**, **인증 후 attack surface**, **binary-only targets**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 흥미로운 상태가 준비될 때까지 target을 실행합니다.
2. 그 시점의 **memory + registers**를 snapshot으로 저장합니다.
3. 각 testcase에서 변형된 입력을 관련 guest/process buffer에 직접 씁니다.
4. crash/timeout/reset이 발생할 때까지 실행합니다.
5. snapshot을 복원합니다. VM target에서 지원된다면 **dirty pages**만 복원한 뒤 반복합니다.

snapshot은 첫 번째 비용이 많이 드는 parse/dispatch 단계와 가능한 한 가까운 위치에 둡니다. 예를 들어 `recv`/`read` 직후나 packet deserialization 지점에 두고, target이 사용하는 입력 buffer를 기록합니다. 이는 작업 반복을 피하기 위해 snapshot을 입력 처리 단계 안쪽으로 옮기는 adaptive-placement 원칙을 따릅니다.<sup>[[11]](#references)</sup>

### 프로토콜 상태를 위한 Incremental snapshots

고정 snapshot은 초기화 비용을 피할 수 있지만, 유효한 메시지가 여러 개 필요한 전이를 그 자체로 탐색하지는 않습니다. LibAFL-Qemu harness는 프로토콜 상태 필드에 대한 쓰기를 감시하고, 상태가 바뀔 때 새 snapshot을 저장할 수 있습니다. [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful)는 `tcpcb.t_state`를 감시하고, 상태와 response flag를 해시해 snapshot 중복을 제거하며, 부모 snapshot을 기준으로 dirty pages를 저장합니다. 다음 구조화된 메시지를 변형하기 전에 부모 체인을 따라 선택한 snapshot을 복원합니다. testcase에는 `SnapshotId`와 생성된 입력 바이트(`gen_bytes`)가 저장되며, snapshot manager는 replay에 필요한 부모 관계를 추적합니다.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu의 user-mode `SnapshotModule`은 mapping과 target memory를 저장하지만 CPU registers는 저장하지 않습니다. 필요한 경우 registers는 별도로 보존하세요. 설명된 manager는 하나의 root snapshot tree만 지원하며 worker 간에 snapshot ID를 공유할 수 없습니다. multi-snapshot 모드에서는 QASAN shadow state도 직접 재사용할 수 없습니다. offline triage를 위해 별도의 instrumented process에서 입력 체인을 재구성하세요. `AsanHostModule`과 `DrCovModule`을 사용할 때는 `fuzzer.evaluate_input`이 필요한 `pre_exec`/`post_exec` callback을 실행하지만, `qemu.run`만으로는 실행하지 않습니다.<sup>[[27]](#references)[[28]](#references)</sup>

### 논리적 ring buffer overread 감지

buffer의 *유효 데이터 개수*를 초과해 읽더라도 host allocation 내부에 머무르면 일반 ASAN을 우회할 수 있습니다. [libslirp urgent-data 예제](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes)에서는 unsigned byte count도 underflow됩니다. source를 사용할 수 있다면 signed/unsigned integer-overflow instrumentation으로 해당 부작용을 감지할 수 있습니다. 보고를 억제하기 전에 의도된 TCP sequence-number wrap과 구분하세요. 더 강력한 oracle로 제안된 방법은 custom ring allocation을 poison 처리하고, 내부 allocator가 진행될 때 유효한 범위만 unpoison 처리한 다음, 해제된 범위를 다시 poison 처리하는 것입니다. LibAFL-Qemu는 source instrumentation이 비현실적인 target을 위한 ASAN poisoning API를 제공합니다.<sup>[[27]](#references)</sup>

## MAccConc를 이용한 Linux Kernel Race 탐색

[MAccConc](https://github.com/googleprojectzero/MAccConc)는 timing에 민감한 Linux-kernel race를 반복 가능한 memory-access schedule로 변환합니다. 두 context의 **A-B-A** 실행을 자동으로 열거하거나, analyst가 terminal UI/GUI에서 순서 제약을 지정할 수 있습니다. 이는 완전한 concurrency fuzzer라기보다 실험적 연구 도구입니다. 현재 LLVM 23+와 프로젝트에서 patch한 kernel이 필요하고, command-line tool은 두 개의 test thread를 지원하며, 제안된 userspace fuzzing layer는 아직 구현되지 않았습니다.<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context communication 지점 수집

KASAN outline callback과 patch된 KCOV memory-record 지원을 사용해 instrumented kernel을 빌드합니다. 프로젝트 README에서는 call stack을 유용하게 유지하도록 sibling-call optimization을 비활성화하는 것도 권장합니다.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`)은 instrumented access를 helper call로 변환합니다. MAccConc kernel patch는 연속된 access가 병합되지 않도록 `asan-opt-same-temp`를 비활성화합니다. 전역 변수 race도 확인해야 한다면 `asan-opt-globals` optimization도 비활성화하세요. KCOV는 결과 레코드를 userspace로 전달합니다. 서로 다른 execution context의 access를 비교하고, byte range가 겹치며 적어도 한쪽이 쓰기인 쌍을 유지합니다. 수명 전환도 후보가 되도록 `kfree()`는 쓰기로 모델링합니다.<sup>[[17]](#references)</sup>

시작한 task를 벗어나는 작업(예: packet processing 또는 RCU callback)의 경우, 해당 subsystem은 KCOV remote-coverage handle을 전달해야 합니다. Upstream remote KCOV는 opt-in 방식이며 임의의 background work에서 자동으로 사용할 수 없으므로, handle 전달이 누락되면 실제 상호작용이 감지되지 않을 수 있습니다.<sup>[[17]](#references)[[19]](#references)</sup>

### 매 실행에서 동일한 동적 access 식별하기

각 allocation 후 바뀔 수 있는 구체적인 heap address만으로 replay하거나, `memcpy()` 및 `spin_lock()` 같은 helper 내부에서 모호한 instruction address만 사용하지 마세요. MAccConc는 **count-augmented stack trace**를 사용합니다. 각 frame은 callee와 caller 내 호출 횟수를 식별하며, 마지막 요소는 memory-access instruction을 식별합니다. SanitizerCoverage의 function-entry/exit 레코드를 사용하면 userspace가 이 동적 식별자를 재구성할 수 있습니다. 이 식별자는 address 변경이나 무관한 control-flow 변동에도 안정적으로 유지됩니다.<sup>[[17]](#references)</sup>

### 후보 쌍을 강제 schedule로 변환하기

패치된 `KCOV_SET_DI` ioctl은 count-augmented access identifier를 shared-flag action과 연결합니다.<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 선택된 access 직전에 flag *N*을 설정합니다. |
| `DI_STACK_WAIT` | 선택된 access 전에 flag *N*이 설정되거나 설정된 제한 시간이 만료될 때까지 spin합니다. |
| `DI_STACK_WAKE_POST` | 선택된 access 직후 flag *N*을 설정합니다. |

부분적인 **A-happens-before-B** 제약을 만들려면 A에 `DI_STACK_WAKE_POST`를, B에 `DI_STACK_WAIT`를 같은 flag로 설정합니다. 두 context의 schedule을 완전히 지정하려면 B를 blocked 상태로 시작한 뒤, 첫 transfer 지점에서 A가 B를 깨우고 기다리게 합니다. 다음 transfer에서는 B가 반대 작업을 수행합니다. 후자는 deterministic context switching처럼 동작하며, 자동 A-B-A explorer가 사용하는 방식입니다.<sup>[[17]](#references)</sup>

최소 campaign에서는 네 개의 hook(`test_setup`, 두 thread function, `test_end`)이 포함된 test case를 shared library로 컴파일하고, 제약이 없는 trace를 수집한 다음 A-B-A 후보를 열거하거나 의심스러운 access 주변에 수동 제약을 추가합니다.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

시간 초과는 성공적인 순서 재배치와 별도로 해석하세요. 잠금이나 초기화/게시 의존성 때문에 두 번째 컨텍스트가 주입 지점에 도달하지 못해 요청한 순서가 불가능할 수 있습니다. 또한 KASAN의 사각지대도 고려하세요. 직접적인 스택 접근은 범위를 벗어날 가능성이 있는 경우가 아니면 대개 후킹되지 않고, 기본 최적화에서는 전역 변수가 제외되며, 현재 컴파일러는 ASAN과 TSAN 후크를 동시에 생성할 수 없습니다. 마지막으로, 프로토타입은 게스트가 패닉을 일으키면 KCOV 버퍼를 잃으므로 별도의 크래시 콘솔/오라클을 유지하세요.<sup>[[17]](#references)</sup>

향후 concurrency-guided fuzzing을 위해 입력 또는 syscall별 메모리 접근 요약을 기록하고, 컨텍스트 간 통신 지점이 될 작업들을 짝지은 다음 해당 조합만 탐색하세요. VM 스냅샷은 전역 상태와 주소를 안정화합니다. 스냅샷이 없다면 할당 지점 메타데이터를 사용해 실행 간 객체를 추상화할 수 있습니다. 이는 제안된 확장이지, 현재 MAccConc userspace 도구의 기능은 아닙니다.<sup>[[17]](#references)</sup>

## 하네스 내부 조사: 얕은 퍼저를 조기에 찾기

캠페인이 정체될 때 문제는 종종 mutator가 아니라 **하네스**에 있습니다. **도달 가능성/커버리지 내부 조사**를 사용해 퍼즈 타깃에서 정적으로 도달 가능하지만 동적으로는 거의 또는 전혀 커버되지 않는 함수를 찾으세요. 이러한 함수는 대개 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- 하네스가 타깃에 너무 늦게 또는 너무 일찍 진입합니다.
- 시드 코퍼스에 기능군 전체가 빠져 있습니다.
- 타깃에는 지나치게 큰 “모든 것을 처리하는” 하네스 하나가 아니라 **두 번째 하네스**가 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일의 워크플로를 사용한다면, Fuzz Introspector가 정적 도달 가능성과 런타임 커버리지를 비교하고 시간 제한 실행 또는 공개 코퍼스를 바탕으로 보고서를 생성할 수 있습니다.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

보고서를 사용해 테스트되지 않은 parser 경로에 새 harness를 추가할지, 특정 기능의 corpus를 확장할지, 아니면 하나로 뭉친 harness를 더 작은 entry point로 분할할지 결정하세요.

## Graph-First Fuzz Target Selection And Mutation Triage

이미 **static-analysis 결과**, **mutation-testing survivor**, **coverage 보고서**가 있다면, 이를 서로 독립된 목록처럼 triage하지 마세요. 먼저 **call graph**를 만들고, 노드에 **cyclomatic complexity**, **entrypoint/신뢰할 수 없는 입력으로부터의 도달 가능성**, 외부 결과를 표시한 다음 graph를 살펴보세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 복잡도가 높고 신뢰할 수 없는 입력에서 도달 가능한 함수는 무엇인가요?
- parser/handler에서 보안상 중요한 코드로 이어지는 경로에 어떤 mutation survivor가 있나요?
- **blast radius**가 유난히 큰 아키텍처상 병목 함수는 무엇인가요?

이 방법은 보통 "coverage가 가장 낮은 항목"만 보는 것보다 더 나은 fuzz target을 찾아냅니다. **복잡도가 높고** **외부에서 도달 가능함이 확인된** parser/decoder는 공격자가 제어하는 경로가 없는 내부 helper보다 더 적합한 harness 후보입니다.

### 실용적인 triage 워크플로

1. 코드베이스에서 **code graph**를 만들고 함수별 복잡도/분기 지표를 추출합니다.
2. 공격자가 제어하는 입력을 받는 **entrypoint**를 열거합니다. 예: request handler, decoder, importer, protocol parser, CLI/file reader.
3. entrypoint에서 후보 함수까지 **경로 쿼리**를 실행해, 도달 가능한 공격 표면과 dead/internal-only 코드를 구분합니다.
4. 다음 조건을 함께 충족하는 노드의 우선순위를 높입니다.
   - 높은 **cyclomatic complexity**
   - 신뢰할 수 없는 입력으로부터의 도달 가능성 확인
   - 높은 **blast radius** 또는 다수의 하위 의존 함수
   - **SARIF** 결과, audit 메모, mutation survivor와 같은 보강 증거
5. 점수가 높은 노드부터 집중된 harness를 작성합니다. 특히 hex/Base64/IP/message decoder 같은 **parser/codec**를 우선합니다.

### Mutation survivor: 동등한 변이체와 조치가 필요한 변이체

Mutation testing은 survivor 목록에 잡음이 많이 섞이는 경우가 많습니다. survivor를 모두 보안 공백으로 취급하기 전에 graph를 사용해 다음을 확인하세요.

- 변이된 함수가 공격자가 제어하는 entrypoint에서 도달 가능한가요?
- 모든 호출 경로에 변이된 검증보다 강한 불변 조건이 적용되나요?
- 해당 노드가 dead code, 서식 처리 전용 로직, 또는 영향이 큰 산술/parser 경로에 있나요?

도달할 수 없거나 구조적으로 제약된 상태로 남는 survivor는 흔히 **equivalent mutant**입니다. 계속 **도달 가능**하며 **경계 조건**, **overflow/carry 경로**, 또는 **보안상 중요한 산술/파싱**을 다루는 survivor는 다음 항목으로 승격해야 합니다.

- 새 fuzz harness
- 직접적인 property/invariant 테스트
- 대상이 명확한 edge-case 벡터

### 외부 결과를 graph에 매핑하기

SAST pipeline에서 **SARIF**를 내보내는 경우, **파일 + 줄 범위**를 기준으로 결과를 graph 노드에 매핑하고 graph를 사용해 영향 범위를 확장하세요.<sup>[[6]](#references)</sup>

- 표시된 함수의 **blast radius**를 계산합니다.
- 해당 결과가 entrypoint에서 이어지는 경로에 있는지 확인합니다.
- 인접한 결과 중 같은 병목으로 모이는 항목을 그룹화합니다.

이는 특정 함수에 fuzzing 시간을 투입할지 결정할 때 유용합니다. **도달 가능하고**, **복잡하며**, 이미 **SAST 결과**가 있는 노드는 공격자 경로가 없는 단순 고복잡도 노드보다 더 나은 target인 경우가 많습니다.

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

중요한 methodology는 **complexity x exposure x impact**의 교집합입니다. 그래프를 활용해 기대 보안 가치가 가장 높은 fuzz target을 고른 다음, mutation survivors를 바탕으로 harness가 집중적으로 테스트해야 할 경계와 불변 조건을 결정하세요.<sup>[[5]](#references)</sup>

## 암호화 키 인코딩의 Differential fuzzing

유효한 직렬화 키나 표준 테스트 벡터에서 시작하세요. import 및 operation 경로에 도달하는 데 필요한 길이와 구조는 유지하면서 인코딩된 필드를 변형한 뒤, 동일한 바이트를 서로 독립적인 구현에 전달하세요. 허용 여부와 오류를 비교하세요. 무작위 서명과 암호문에는 바이트 단위 비교가 아닌 정확성 oracle이 필요합니다. 서명을 검증하거나 encapsulation/decapsulation 왕복 과정에서 shared secret을 비교하세요. 테스트 벡터는 알려진 사례에 대한 적합성을 확인하고, differential mutation은 그 외의 잘못된 인코딩을 탐색합니다.<sup>[[23]](#references)[[26]](#references)</sup>

다음 키 형식에는 형식별 oracle을 사용하세요:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** 키를 파싱할 수 있는 상태로 유지하면서 packed `s1` 또는 `s2` 계수를 `[-η, η]` 범위를 벗어나게 변형하세요. import 또는 signing 과정에서 거부되는지, 생성된 서명이 검증되는지 확인하세요. 허용 여부의 차이만으로 표준 위반이라고 볼 수는 없습니다. FIPS 204는 추가적인 private-key 검사를 의무화하지 않기 때문입니다. [conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)을 참고하세요.
- **ML-KEM key pairs:** 필수 encapsulation-key 및 decapsulation-input 검사와, 가져온 키 쌍에 선택적으로 적용되는 pairwise-consistency check(PCT)를 구분하세요. 공개 키로 encapsulate하고 개인 키로 decapsulate한 다음 shared secret을 비교하세요. 개별 키가 입력 검사를 통과하더라도 값이 일치하지 않으면 암호화된 통신이 중단될 수 있습니다. API가 입력을 operation 내에서 검증하는지 별도 호출로 검증하는지 확인하세요. libcrux는 `validate_public_key(pk)`와 `validate_private_key(sk, ct)`를 제공하지만, 이들은 PCT를 대체하지 않습니다.
- **XMSS/XMSSMT raw keys:** 메모리 내 키로 operation만 테스트하지 말고, 여러 parameter set에서 직렬화된 **signing 및 verifying** 키의 왕복을 테스트하세요. XMSS와 XMSSMT는 서로 다른 4바이트 OID namespace를 사용하므로 XMSS를 먼저 시도하는 OID 전용 parser는 OID가 충돌하는 XMSSMT 키를 잘못 분류해 import를 거부할 수 있습니다. 보고된 RustCrypto parser 사례는 서명 위조가 아니라 interoperability/availability 실패를 보여 줍니다.

## gosentry를 사용한 Go Fuzzing: 더 강력한 엔진, 타입이 지정된 입력 및 Differential 검사

Go target에 이미 기본 `testing.F` harness가 있다면, 실용적인 업그레이드 방법은 같은 harness를 [gosentry](https://github.com/trailofbits/gosentry)로 실행하는 것입니다. gosentry는 `go test -fuzz`는 유지하면서 백엔드를 **LibAFL**로 교체한 포크된 Go toolchain입니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

이는 native Go fuzzer가 **hard comparisons**, **typed inputs** 또는 **parser-heavy formats**에서 멈출 때 유용합니다. 방법론은 동일합니다.

- seed에는 계속 `f.Add(...)`를, callback에는 `f.Fuzz(...)`를 사용합니다.
- 동일한 harness를 재사용하되, stock toolchain 대신 gosentry의 `go` 바이너리로 실행합니다.
- 결과 campaign은 일반적인 coverage-guided 실행으로 취급하되, LibAFL의 scheduling/mutation과 더 나은 주변 detector를 활용합니다.

### 조용한 실패를 fuzz 탐지 결과로 전환하기

Go 평가에서 반복적으로 발생하는 문제는 위험한 동작이 기본적으로 **crash를 일으키지 않는** 경우가 많다는 점입니다. gosentry를 사용하면 여러 유형의 "나쁘지만 조용한" 상태를 탐지 결과로 전환할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용하면 선택한 logging/error 경로가 crash처럼 동작합니다. (그렇지 않으면 로그만 남기고 계속 실행하는 `log.Fatal` 스타일 코드 경로에 유용합니다.)
- `--catch-races=true`를 사용하면 새로 발견된 queue 항목을 Go race detector로 재실행합니다.
- `--catch-leaks=true`를 사용하면 새 queue 항목을 `goleak`으로 재실행하고 goroutine leak이 발생하면 중단합니다.
- LibAFL의 hang 처리를 사용하면 **infinite loop / 매우 느린 input**이 timeout으로 사라지지 않고 fuzz 탐지 결과로 남습니다.
- 기본적으로 내장된 arithmetic overflow 검사를 제공하며, go-panikint 스타일 instrumentation을 통해 선택적으로 truncation 검사도 수행할 수 있습니다.

이는 보안 영향이 memory corruption이 아니라 **panicless parser failure**, **concurrency bug** 또는 **DoS만 유발하는 hang**인 대상에 특히 유용합니다.

### Typed Go API를 위한 struct-aware fuzzing

Native Go fuzzing은 주로 `[]byte`, `string`, 숫자와 같은 scalar를 예상합니다. 테스트 대상 코드가 typed object를 입력으로 받는 경우, gosentry는 내부적으로 계속 byte를 변형하면서 struct, slice, array, pointer 등의 **composite value**를 직접 fuzz할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing만을 위해 가짜 wire format을 만들면 harness에서만 사용하는 parsing code 뒤에 logic bug가 숨겨질 수 있습니다. differential 또는 grammar-based 캠페인에서는 harness 입력을 단일 `[]byte` 또는 `string`으로 유지하고, 대신 callback 내부에서 parsing하세요.

### parser 및 protocol 입력을 위한 grammar-based fuzzing

parser, format, input language의 경우 gosentry는 LibAFL을 기반으로 **Nautilus grammar fuzzing**을 실행할 수 있습니다. grammar는 production rule로 구성된 JSON array이며, harness는 보통 단일 `[]byte` 또는 `string` 인수를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- byte-level mutations가 대부분 초기 syntax 검사에서 실패한다면 grammar mode를 사용합니다.
- 전체 specification을 모델링하는 대신, language/protocol의 **보안 관련 하위 집합**에 grammar를 집중합니다.
- terminal/nonterminal에 큰 경계값을 사용해 integer, length, state-machine 경계를 자극합니다.
- grammar mode는 입력을 grammar-valid 상태로 유지하지만, 대상에는 여전히 **bytes/strings**가 전달되므로 parsing과 semantic 검사는 harness로 감싼 코드 안에서 수행됩니다.

### Differential fuzzing: crash뿐 아니라 구현 간 비교

Go 생태계에서 효과적인 패턴은 **grammar-based differential fuzzing**입니다. 유효한 구조화 입력을 생성해 두 parser, client 또는 state-transition engine에 전달합니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

다음 항목은 문제점으로 간주합니다.

- 한 구현은 panic이 발생하지만 다른 구현은 정상적으로 거부함
- 입력을 수락하거나 거부하는 결과가 서로 다름
- 구문 분석 트리 또는 디코딩된 객체가 서로 다름
- 상태 전이, nonce, 잔액 또는 state root가 서로 다름

이는 순수 crash fuzzing으로는 놓치기 쉬운 **합의 불일치**, **parser 모호성**, **사양과 구현 간의 괴리**를 찾는 실용적인 방법입니다.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 커버리지 보고에 캠페인 코퍼스 재사용하기

캠페인이 끝난 뒤 저장된 큐 코퍼스를 재실행하면 별도의 코퍼스를 수동으로 내보내지 않고도 Go 커버리지 보고서를 생성할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

같은 package에서 동일한 `-fuzz` target으로 명령을 실행해야 gosentry가 올바른 캐시된 campaign state를 확인합니다.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ 퍼징 심층 분석](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [5년 후의 AFLNet: 커버리지 기반 프로토콜 퍼징에 관하여](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark, 코드를 그래프로 변환하다](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing에는 도구 모음의 절반이 빠져 있었습니다. 이를 해결하기 위해 toolchain을 fork했습니다.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 스냅샷을 사용하는 상태 저장 네트워크 프로토콜용 고속 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [문법이 없어도 문제없다: 시스템 호출 설명 없이 Linux 커널을 퍼징하는 방법](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: 적응형 및 변경 가능한 스냅샷을 활용한 효율적인 퍼징](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 계측: 경로 및 호출자 커버리지](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [예측적 컨텍스트 민감 퍼징](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 빌드 및 회귀 시드 문서](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: 제어된 메모리 접근 인터리빙으로 Linux 커널 경쟁 조건 탐색하기](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: 퍼징을 위한 코드 커버리지](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 확장 파일명 구문](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 권고문: CFITSIO 2025년 4분기](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO 확장 파일명 구문 퍼징: 메모리 안전성 취약점 16건 및 Codex 지원 분류](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [암호학을 위한 차등 퍼징](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: 모듈 격자 기반 키 캡슐화 메커니즘 표준](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID 파싱 버그 - RustCrypto 이슈 #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [양자내성 암호 구현 현황](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [스냅샷으로 CVE-2026-9539에 이르기까지](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzer 대 AI: JavaScript 엔진에서 Fuzzilli과 BigSleep 비교](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
