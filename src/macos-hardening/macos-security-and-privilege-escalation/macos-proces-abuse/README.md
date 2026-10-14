# macOS 프로세스 악용

{{#include ../../../banners/hacktricks-training.md}}

## 프로세스 기본 정보

프로세스는 실행 중인 실행 파일의 인스턴스입니다. 하지만 프로세스가 코드를 실행하는 것은 아니며, 실제로 코드를 실행하는 것은 스레드입니다. 따라서 **프로세스는 스레드를 실행하기 위한 컨테이너일 뿐이며**, 메모리, 디스크립터, 포트, 권한 등을 제공합니다.

전통적으로 PID 1을 제외한 프로세스는 **`fork`**를 호출해 다른 프로세스 안에서 시작되었습니다. `fork`는 현재 프로세스의 완전한 복사본을 만들고, **자식 프로세스**는 일반적으로 **`execve`**를 호출해 새 실행 파일을 로드하고 실행했습니다. 이후 메모리 복사 없이 이 과정을 더 빠르게 수행하기 위해 **`vfork`**가 도입되었습니다.\
그다음 **`vfork`**와 **`execve`**를 한 번의 호출로 결합하고 플래그를 받는 **`posix_spawn`**이 도입되었습니다.

- `POSIX_SPAWN_RESETIDS`: 유효 ID를 실제 ID로 재설정
- `POSIX_SPAWN_SETPGROUP`: 프로세스 그룹 소속 설정
- `POSUX_SPAWN_SETSIGDEF`: 기본 시그널 동작 설정
- `POSIX_SPAWN_SETSIGMASK`: 시그널 마스크 설정
- `POSIX_SPAWN_SETEXEC`: 동일한 프로세스에서 실행 (`execve`와 유사하지만 옵션이 더 많음)
- `POSIX_SPAWN_START_SUSPENDED`: 일시 중단된 상태로 시작
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR 없이 시작
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc의 Nano allocator 사용
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 데이터 세그먼트에서 `rwx` 허용
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 기본적으로 exec(2) 시 모든 파일 디스크립션 닫기
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR 슬라이드의 상위 비트를 무작위화

또한 `posix_spawn`은 생성된 프로세스의 동작을 제어하는 **`posix_spawnattr`** 설정과 파일 디스크립터를 수정하는 **`posix_spawn_file_actions`** 항목을 받습니다.

프로세스가 종료되면 **종료 코드를 부모 프로세스에 전달**합니다(부모가 이미 종료된 경우 새 부모는 PID 1입니다). 이때 `SIGCHLD` 시그널을 보냅니다. 부모는 `wait4()` 또는 `waitid()`를 호출해 이 값을 가져와야 합니다. 그때까지 자식 프로세스는 목록에 남아 있지만 리소스를 소비하지 않는 좀비 상태로 유지됩니다.

### PIDs

PID(프로세스 식별자)는 고유한 프로세스를 식별합니다. XNU에서 **PID**는 **64비트**이며 단조 증가하고 **절대 순환하지 않습니다**(악용을 방지하기 위해).

### 프로세스 그룹, 세션 및 코얼리션

**프로세스**를 **그룹**으로 묶으면 관리하기 쉬워집니다. 예를 들어 셸 스크립트의 명령은 같은 프로세스 그룹에 속하므로 `kill` 등을 사용해 **함께 시그널을 보낼 수 있습니다**.\
프로세스를 **세션으로 그룹화**할 수도 있습니다. 프로세스가 세션을 시작하면(`setsid(2)`), 자체 세션을 시작하지 않는 한 자식 프로세스는 해당 세션에 속하게 됩니다.

코얼리션은 Darwin에서 프로세스를 그룹화하는 또 다른 방법입니다. 프로세스가 코얼리션에 참여하면 풀 리소스에 접근하고, 원장을 공유하거나 Jetsam의 적용을 받을 수 있습니다. 코얼리션에는 Leader, XPC service, Extension 등 다양한 역할이 있습니다.

### 자격 증명 및 페르소나

각 프로세스는 시스템에서의 권한을 **식별하는 자격 증명**을 보유합니다. 각 프로세스에는 기본 `uid` 하나와 기본 `gid` 하나가 있습니다(여러 그룹에 속할 수는 있음).\
바이너리에 `setuid/setgid` 비트가 설정되어 있으면 사용자 및 그룹 ID를 변경할 수도 있습니다.\
새 uid/gid를 **설정하는** 함수는 여러 가지가 있습니다.

시스템 호출 **`persona`**는 **대체 자격 증명** 집합을 제공합니다. 페르소나를 채택하면 해당 페르소나의 uid, gid, 그룹 멤버십을 **한 번에** 적용합니다. [**소스 코드**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)에서 다음 구조체를 확인할 수 있습니다:

```c
struct kpersona_info { uint32_t persona_info_version;
    uid_t    persona_id; /* overlaps with UID */
    int      persona_type;
    gid_t    persona_gid;
    uint32_t persona_ngroups;
    gid_t    persona_groups[NGROUPS];
    uid_t    persona_gmuid;
    char     persona_name[MAXLOGNAME + 1];

    /* TODO: MAC policies?! */
}
```

## 스레드 기본 정보

1. **POSIX Threads (pthreads):** macOS는 C/C++용 표준 스레딩 API의 일부인 POSIX 스레드(`pthreads`)를 지원합니다. macOS의 pthreads 구현은 공개적으로 제공되는 `libpthread` 프로젝트에서 제공하는 `/usr/lib/system/libsystem_pthread.dylib`에 있습니다. 이 라이브러리는 스레드를 생성하고 관리하는 데 필요한 함수를 제공합니다.
2. **스레드 생성:** `pthread_create()` 함수는 새 스레드를 생성하는 데 사용됩니다. 내부적으로 이 함수는 XNU 커널(macOS의 기반 커널)에 특화된 저수준 시스템 호출인 `bsdthread_create()`를 호출합니다. 이 시스템 호출은 스케줄링 정책 및 스택 크기를 포함해 스레드 동작을 지정하는 `pthread_attr`(속성)에서 파생된 다양한 플래그를 사용합니다.
   - **기본 스택 크기:** 새 스레드의 기본 스택 크기는 512 KB입니다. 일반적인 작업에는 충분하지만, 필요한 경우 스레드 속성을 사용해 크기를 늘리거나 줄일 수 있습니다.
3. **스레드 초기화:** `__pthread_init()` 함수는 스레드 설정 과정에서 중요한 역할을 합니다. 이 함수는 `env[]` 인수를 사용해 스택의 위치와 크기에 관한 정보가 포함될 수 있는 환경 변수를 파싱합니다.

#### macOS의 스레드 종료

1. **스레드 종료:** 일반적으로 스레드는 `pthread_exit()`를 호출해 종료됩니다. 이 함수는 스레드를 깔끔하게 종료하고 필요한 정리 작업을 수행하며, 조인하는 스레드에 반환 값을 전달할 수 있게 합니다.
2. **스레드 정리:** `pthread_exit()`를 호출하면 `pthread_terminate()` 함수가 호출되어 관련된 모든 스레드 구조체를 제거합니다. 이 함수는 Mach 스레드 포트(Mach는 XNU 커널의 통신 하위 시스템)를 해제하고, 스레드와 관련된 커널 수준 구조체를 제거하는 시스템 호출인 `bsdthread_terminate`를 호출합니다.

#### 동기화 메커니즘

공유 리소스에 대한 접근을 관리하고 경쟁 상태를 방지하기 위해 macOS는 여러 동기화 기본 요소를 제공합니다. 이는 데이터 무결성과 시스템 안정성을 보장하는 데 필요한 다중 스레드 환경에서 중요한 요소입니다.

1. **뮤텍스:**
   - **일반 뮤텍스 (시그니처: 0x4D555458):** 메모리 크기가 60바이트인 표준 뮤텍스입니다(뮤텍스에 56바이트, 시그니처에 4바이트).
   - **Fast Mutex (시그니처: 0x4d55545A):** 일반 뮤텍스와 비슷하지만 더 빠른 작업을 위해 최적화되어 있으며, 크기도 60바이트입니다.
2. **조건 변수:**
   - 특정 조건이 발생할 때까지 기다리는 데 사용되며, 크기는 44바이트입니다(40바이트에 시그니처 4바이트).
   - **조건 변수 속성 (시그니처: 0x434e4441):** 조건 변수의 설정 속성으로, 크기는 12바이트입니다.
3. **Once 변수 (시그니처: 0x4f4e4345):**
   - 초기화 코드가 한 번만 실행되도록 보장합니다. 크기는 12바이트입니다.
4. **읽기-쓰기 잠금:**
   - 여러 읽기 작업 또는 한 번에 하나의 쓰기 작업을 허용하여 공유 데이터에 효율적으로 접근할 수 있게 합니다.
   - **읽기-쓰기 잠금 (시그니처: 0x52574c4b):** 크기는 196바이트입니다.
   - **읽기-쓰기 잠금 속성 (시그니처: 0x52574c41):** 읽기-쓰기 잠금의 속성으로, 크기는 20바이트입니다.

> [!TIP]
> 이러한 객체의 마지막 4바이트는 오버플로를 감지하는 데 사용됩니다.

### 스레드 로컬 변수 (TLV)

Mach-O 파일(macOS 실행 파일 형식)에서 **스레드 로컬 변수 (TLV)** 는 다중 스레드 애플리케이션에서 **각 스레드별로** 사용하는 변수를 선언하는 데 쓰입니다. 이를 통해 각 스레드가 변수의 개별 인스턴스를 가지므로, 뮤텍스와 같은 명시적 동기화 메커니즘 없이도 충돌을 방지하고 데이터 무결성을 유지할 수 있습니다.

C 및 관련 언어에서는 **`__thread`** 키워드를 사용해 스레드 로컬 변수를 선언할 수 있습니다. 다음 예제에서는 이렇게 동작합니다:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

이 스니펫은 `tlv_var`를 thread-local 변수로 정의합니다. 이 코드를 실행하는 각 스레드는 고유한 `tlv_var`를 가지며, 한 스레드에서 `tlv_var`를 변경해도 다른 스레드의 `tlv_var`에는 영향을 주지 않습니다.

Mach-O 바이너리에서 thread-local 변수와 관련된 데이터는 특정 섹션에 구성됩니다.

- **`__DATA.__thread_vars`**: 이 섹션에는 thread-local 변수의 유형과 초기화 상태 같은 메타데이터가 들어 있습니다.
- **`__DATA.__thread_bss`**: 명시적으로 초기화되지 않은 thread-local 변수에 사용되는 섹션입니다. 0으로 초기화되는 데이터를 위해 따로 마련된 메모리 영역입니다.

Mach-O는 스레드가 종료될 때 thread-local 변수를 관리하는 **`tlv_atexit`**이라는 특정 API도 제공합니다. 이 API를 사용하면 스레드가 종료될 때 thread-local 데이터를 정리하는 특수 함수인 **destructor를 등록**할 수 있습니다.

### 스레드 우선순위

스레드 우선순위를 이해하려면 운영체제가 어떤 스레드를 언제 실행할지 결정하는 방식을 살펴봐야 합니다. 이 결정은 각 스레드에 할당된 우선순위 수준의 영향을 받습니다. macOS 및 Unix 계열 시스템에서는 `nice`, `renice`, Quality of Service (QoS) 클래스 등의 개념을 사용해 이를 처리합니다.

#### Nice와 Renice

1. **Nice:**
   - 프로세스의 `nice` 값은 우선순위에 영향을 주는 숫자입니다. 모든 프로세스는 -20(가장 높은 우선순위)부터 19(가장 낮은 우선순위)까지의 `nice` 값을 가집니다. 프로세스 생성 시 기본 `nice` 값은 일반적으로 0입니다.
   - `nice` 값이 낮을수록(-20에 가까울수록) 프로세스가 더 "이기적"으로 동작하며, `nice` 값이 더 높은 다른 프로세스보다 더 많은 CPU 시간을 얻습니다.
2. **Renice:**
   - `renice`는 이미 실행 중인 프로세스의 `nice` 값을 변경하는 명령어입니다. 새 `nice` 값에 따라 CPU 시간 할당량을 늘리거나 줄여 프로세스 우선순위를 동적으로 조정할 수 있습니다.
   - 예를 들어, 프로세스에 일시적으로 더 많은 CPU 리소스가 필요하다면 `renice`를 사용해 `nice` 값을 낮출 수 있습니다.

#### Quality of Service (QoS) 클래스

QoS 클래스는 특히 **Grand Central Dispatch (GCD)**를 지원하는 macOS 같은 시스템에서 스레드 우선순위를 처리하는 보다 현대적인 방식입니다. QoS 클래스를 사용하면 개발자가 작업의 중요도나 긴급성에 따라 작업을 **분류**할 수 있습니다. macOS는 이러한 QoS 클래스에 따라 스레드 우선순위를 자동으로 관리합니다.

1. **User Interactive:**
   - 현재 사용자와 상호작용 중이거나 좋은 사용자 경험을 위해 즉각적인 결과가 필요한 작업에 사용됩니다. 인터페이스의 반응성을 유지하기 위해 가장 높은 우선순위가 부여됩니다(예: 애니메이션 또는 이벤트 처리).
2. **User Initiated:**
   - 문서 열기나 계산이 필요한 버튼 클릭처럼 사용자가 시작하고 즉각적인 결과를 기대하는 작업입니다. 우선순위가 높지만 User Interactive보다 낮습니다.
3. **Utility:**
   - 장시간 실행되며 일반적으로 진행률 표시기를 보여 주는 작업입니다(예: 파일 다운로드, 데이터 가져오기). 사용자 시작 작업보다 우선순위가 낮으며 즉시 완료할 필요는 없습니다.
4. **Background:**
   - 백그라운드에서 실행되며 사용자에게 보이지 않는 작업에 사용됩니다. 색인 생성, 동기화, 백업 등이 이에 해당합니다. 우선순위가 가장 낮으며 시스템 성능에 미치는 영향도 최소화됩니다.

QoS 클래스를 사용하면 개발자는 정확한 우선순위 숫자를 직접 관리하는 대신 작업의 특성에 집중할 수 있으며, 시스템은 이에 맞춰 CPU 리소스를 최적화합니다.

또한 scheduler가 고려할 scheduling 파라미터 집합을 지정하는 **thread scheduling policy**도 여러 가지 있습니다. `thread_policy_[set/get]`을 사용해 설정할 수 있으며, race condition attack에 유용할 수 있습니다.

## macOS 프로세스 악용

macOS는 **프로세스가 상호작용하고 통신하며 데이터를 공유할 수 있도록** 다양한 메커니즘을 제공합니다. 이러한 메커니즘은 정상적인 시스템 작동에 필수적이지만, 공격자는 이를 악용해 injection, code execution 또는 data access를 수행할 수 있습니다.

### Library Injection

Library Injection은 공격자가 **프로세스에 악성 라이브러리를 강제로 로드하는** 기법입니다. 라이브러리를 주입하면 대상 프로세스의 컨텍스트에서 실행되므로, 공격자는 해당 프로세스와 동일한 권한 및 접근 권한을 얻게 됩니다.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking은 소프트웨어 코드 내의 **함수 호출**이나 메시지를 **가로채는** 기법입니다. 함수를 hook하면 공격자는 프로세스의 **동작을 변경**하거나, 민감한 데이터를 관찰하거나, 실행 흐름을 제어할 수도 있습니다.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

이 페이지에서는 ARM64 unwind 메타데이터, arm64e PAC 제약 사항, synthetic call chain을 다룹니다.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### 프로세스 간 통신

프로세스 간 통신(IPC)은 별도의 프로세스가 **데이터를 공유하고 교환하는** 다양한 방법을 가리킵니다. IPC는 많은 합법적인 애플리케이션에 필수적이지만, 프로세스 격리를 무력화하거나 민감한 정보를 leak하거나 권한 없는 작업을 수행하는 데 악용될 수도 있습니다.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron 애플리케이션 Injection

특정 환경 변수를 사용해 실행되는 Electron 애플리케이션은 process injection에 취약할 수 있습니다:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` 및 `--use-fake-ui-for-media-stream` 플래그를 사용하면 **man in the browser attack**을 수행해 키 입력, 트래픽, 쿠키를 훔치고 페이지에 스크립트를 주입할 수 있습니다...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB 파일은 애플리케이션 내의 **사용자 인터페이스(UI) 요소와 상호작용을 정의**합니다. 하지만 이 파일은 **임의의 명령을 실행할 수 있으며**, **NIB 파일이 수정된 경우 Gatekeeper는 이미 실행된 애플리케이션의 재실행을 차단하지 않습니다**. 따라서 이를 이용해 임의의 프로그램이 임의의 명령을 실행하도록 할 수 있습니다:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java 애플리케이션 Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** 또는 **`JDK_JAVA_OPTIONS`**를 통해 JVM 옵션을 주입하고 애플리케이션 시작 전에 Java 또는 native agent를 로드할 수 있습니다.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**는 `--require`(파일) 또는 `--import data:text/javascript,…`(fileless, Node ≥ 20.6)를 통해 공격자의 JavaScript를 preload합니다. **`NODE_REPL_EXTERNAL_MODULE`**은 모듈을 대화형 REPL로 로드하며, **`ELECTRON_RUN_AS_NODE`**는 Electron 바이너리에서 이 모든 기능을 다시 활성화합니다.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net 애플리케이션 Injection

`Main` 실행 전에 **`DOTNET_STARTUP_HOOKS`**를 사용하거나, 필요한 전제 조건이 충족된 경우 .NET debugging 기능을 악용해 .NET 애플리케이션에 코드를 주입할 수 있습니다.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

비대화형 Bash는 **`BASH_ENV`**를 읽고, 대화형 POSIX shell은 **`ENV`**를 읽습니다. zsh는 **`$ZDOTDIR/.zshenv`**를 읽으며, fish는 **`XDG_CONFIG_HOME`** 또는 **`XDG_DATA_DIRS`** 아래의 설정 파일을 읽습니다. 각 shell은 제어된 시작 파일을 의도한 명령보다 먼저 실행할 수 있습니다. 또한 Bash는 xtrace가 활성화되어 있을 때(예: **`SHELLOPTS=xtrace`**를 상속한 경우) **`PS4`**에 포함된 command substitution을 실행합니다:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s`를 시작하면 shell은 표준 입력에서 프로그램을 읽습니다. 따라서 신뢰할 수 없는 구조화된 문서를 먼저 파싱하지 않고 자식 프로세스의 stdin으로 복사하는 downloader는 문서 전체를 shell source로 바꾸게 됩니다. 실제로 관찰된 한 loader는 공개 iCalendar 파일을 익명 pipe를 통해 한 줄씩 전달했습니다. 캘린더 메타데이터는 명령어로 실행되지 않았지만, zsh는 계속 실행하다가 `DESCRIPTION:` 뒤에 삽입된 실행 가능한 줄에 도달했습니다. 해당 줄은 다음 애플리케이션 bundle을 다운로드하고 실행했습니다. 전달 매체의 예상 콘텐츠 유형과 신뢰할 수 있는 호스팅은 이를 안전하게 만들지 않습니다. 위험한 경계는 해당 바이트를 interpreter에 전달하는 것이었습니다.<sup>[[5]](#references)</sup>

관련 단계는 [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), [macOS auto-start locations](../../macos-auto-start-locations.md)에서 다룹니다.

### PHP Injection

**`PHPRC`** 또는 **`PHP_INI_SCAN_DIR`**를 사용하면 **`auto_prepend_file`**이 대상 스크립트보다 먼저 실행되는 제어된 PHP 설정 파일을 로드할 수 있습니다.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

독립 실행형 Lua interpreter는 대상 스크립트를 처리하기 전에 **`LUA_INIT`**(또는 버전별 변형)에 지정된 코드나 `@file`을 실행합니다.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** 및 **`R_PROFILE`**은 R 코드가 포함된 시작 프로필을 다른 위치로 지정합니다. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**와 R library path를 함께 사용하면 설치된 패키지를 자동으로 로드할 수도 있습니다.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**는 `config/startup.jl`이 자동으로 실행되는 depot의 경로를 변경합니다.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang 및 Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** 또는 **`ERL_ZFLAGS`**를 사용하면 payload 파일 없이 Erlang VM **`-eval`** 표현식을 주입할 수 있습니다. Elixir workload도 일반적으로 동일한 VM을 시작합니다.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 및 **`OCTAVE_VERSION_INITFILE`**은 Octave 시작 스크립트의 경로를 변경합니다.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh`는 크로스 플랫폼 .NET 앱이므로 여러 환경 변수를 통해 명령 실행 전에 코드를 실행할 수 있습니다. **`XDG_CONFIG_HOME`**은 시작 시 실행되는 프로필 스크립트의 경로를 변경하고, **`PSModulePath`**는 모듈 자동 로딩을 hijack합니다(심어 둔 `.psm1`은 import 시 실행되며 기본 제공 cmdlet을 shadow할 수 있습니다). 또한 .NET의 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 및 **`DOTNET_STARTUP_HOOKS`** 변수는 `Main` 실행 전에 공격자 코드를 프로세스에 로드합니다.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

다음에서 Perl 스크립트가 임의 코드를 실행하게 만드는 여러 방법을 확인하세요:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby 환경 변수(**`RUBYOPT`**, **`RUBYLIB`**)를 악용해 임의의 스크립트가 임의 코드를 실행하게 할 수도 있습니다:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`**와 표준 라이브러리를 통한 **`BROWSER`** chain은 warning-filter 파싱 중에 명령을 실행할 수 있습니다. 파일을 사용하는 대안으로는 **`PYTHONPATH`**에 `sitecustomize.py`를 배치해 일반적인 `site` 초기화 과정에서 대상 스크립트보다 먼저 이를 import하게 하는 방법이 있습니다. **`PYTHONBREAKPOINT`**는 코드가 `breakpoint()`에 도달할 때 지정된 callable/module을 실행합니다. **`PYTHONSTARTUP`** 같은 대화형 전용 변수는 적용 범위가 더 제한적입니다.

**`pyinstaller`**로 컴파일된 실행 파일은 내장된 Python을 사용해 실행되더라도 이러한 환경 변수를 사용하지 않습니다.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

일반적인 시작 과정에서 **`VIMINIT`**(및 대체 변수인 `EXINIT`)은 Ex 명령으로 실행됩니다. 따라서 피해자가 제어된 환경에서 Vim/Neovim을 열면 `:!cmd` / `:call system(...)`을 통해 code execution이 가능합니다:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

별도로 Homebrew는 Python을 `/opt/homebrew` 아래에 설치하는 경우가 많으며, 이 위치에서는 로컬 `admin` 그룹 구성원이 launcher를 교체할 수 있습니다. 이는 환경 변수 injection이 아니라 쓰기 가능한 바이너리 hijack입니다. 악용 가능하다고 판단하기 전에 소유권과 ACL을 확인하세요.


## 탐지

### Shield

[**Shield**](https://github.com/theevilbit/Shield)는 process injection을 탐지하고 차단하는 오픈소스 **EndpointSecurity** 기반 애플리케이션입니다. Endpoint Security를 통해 어떤 신호를 관찰할 수 있는지 보여 주는 참고 자료로도 유용하며, 다음 항목에 경고를 표시합니다:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- 프로세스 실행 시의 **injection 환경 변수**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH`, `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** 호출 — 한 프로세스가 다른 프로세스의 task port를 요청하는 것으로, 해당 프로세스에 injection을 수행하기 위한 전제 조건입니다.
- **Electron debugging 인수** — `--inspect`, `--inspect-brk`, `--remote-debugging-port`. 이 인수는 Electron 앱을 debug mode로 시작해 누구나 연결하여 코드를 실행할 수 있게 합니다.<sup>[[3]](#references)</sup>
- **권한 수준이 다른 위치 간의 symlink/hardlink 생성** — 일반 사용자가 link를 만들어 권한이 높은 위치를 가리키게 하는 전형적인 primitive입니다. **symlink는 경고할 수 있지만 차단할 수는 없습니다**. EndpointSecurity는 link가 생성되기 전에 대상 경로를 제공하지 않기 때문입니다.

### 다른 프로세스가 수행한 호출

[**이 블로그 게시물**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)에서 **`task_name_for_pid`** 함수를 사용해 **프로세스에 코드를 주입하는 다른 프로세스**에 대한 정보를 얻고, 이어서 해당 프로세스에 대한 정보를 확인하는 방법을 볼 수 있습니다.<sup>[[4]](#references)</sup>

이 함수를 호출하려면 해당 프로세스를 실행하는 사용자와 **동일한 uid**이거나 **root**여야 합니다. (이 함수는 프로세스에 대한 정보를 반환할 뿐, 코드를 주입하는 방법을 제공하지 않습니다.)

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — 오픈소스 macOS process injection 탐지 (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity 프레임워크](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron 앱이 비밀 정보를 기밀로 저장할 수 없는 이유: --inspect 옵션](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modification 탐지](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - 암호화폐 애호가와 개발자를 노리는 MacSync macOS stealer의 새 버전](https://securelist.com/macsync-new-version/121383/)
