# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## 프로세스 기본 정보

프로세스는 실행 중인 실행 파일의 인스턴스입니다. 하지만 프로세스가 코드를 실행하는 것은 아닙니다. 코드를 실행하는 것은 스레드입니다. 따라서 **프로세스는 메모리, 파일 디스크립터, 포트, 권한 등을 제공하는 스레드 실행용 컨테이너일 뿐입니다.**

전통적으로 프로세스는 다른 프로세스(PID 1 제외) 내에서 **`fork`**를 호출해 시작했습니다. `fork`는 현재 프로세스의 정확한 복사본을 만들며, 이후 **자식 프로세스**는 일반적으로 **`execve`**를 호출해 새 실행 파일을 로드하고 실행합니다. 이후 메모리 복사 없이 이 프로세스를 더 빠르게 수행하도록 **`vfork`**가 도입되었습니다.\
그다음 **`vfork`**와 **`execve`**를 한 번의 호출로 결합하고 플래그를 받는 **`posix_spawn`**이 도입되었습니다.

- `POSIX_SPAWN_RESETIDS`: 유효 ID를 실제 ID로 재설정
- `POSIX_SPAWN_SETPGROUP`: 프로세스 그룹 소속 설정
- `POSUX_SPAWN_SETSIGDEF`: 신호의 기본 동작 설정
- `POSIX_SPAWN_SETSIGMASK`: 신호 마스크 설정
- `POSIX_SPAWN_SETEXEC`: 동일한 프로세스에서 exec 수행(옵션이 더 많은 `execve`와 유사)
- `POSIX_SPAWN_START_SUSPENDED`: 일시 중단된 상태로 시작
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR 없이 시작
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc의 Nano allocator 사용
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 데이터 세그먼트에서 `rwx` 허용
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 기본적으로 exec(2) 시 모든 파일 디스크립션 닫기
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR 슬라이드의 상위 비트 무작위화

또한 `posix_spawn`은 생성되는 프로세스의 동작을 제어하는 **`posix_spawnattr`** 설정과 파일 디스크립터를 수정하는 **`posix_spawn_file_actions`** 항목을 받습니다.

프로세스가 종료되면 `SIGCHLD` 신호와 함께 **종료 코드를 부모 프로세스에 전송**합니다(부모가 종료된 경우 새 부모는 PID 1입니다). 부모는 `wait4()` 또는 `waitid()`를 호출해 이 값을 가져와야 합니다. 그때까지 자식 프로세스는 목록에는 계속 표시되지만 리소스를 소비하지 않는 좀비 상태로 남습니다.

### PID

PID(프로세스 식별자)는 고유한 프로세스를 식별합니다. XNU에서 **PID**는 **64비트**이며 단조 증가하고 **절대 순환하지 않습니다**(악용 방지 목적).

### 프로세스 그룹, 세션 및 Coalations

**프로세스**를 **그룹**에 넣으면 프로세스를 더 쉽게 관리할 수 있습니다. 예를 들어 셸 스크립트의 명령은 동일한 프로세스 그룹에 속하므로, `kill` 등을 사용해 **한꺼번에 신호를 보낼 수 있습니다.**\
프로세스를 **세션으로 그룹화**하는 것도 가능합니다. 프로세스가 세션을 시작하면(`setsid(2)`), 자식 프로세스는 자체 세션을 시작하지 않는 한 해당 세션에 속하게 됩니다.

Coalition은 Darwin에서 프로세스를 그룹화하는 또 다른 방식입니다. 프로세스가 Coalition에 참여하면 풀 리소스에 접근하고, 원장을 공유하거나 Jetsam의 대상이 될 수 있습니다. Coalition에는 Leader, XPC service, Extension 등 서로 다른 역할이 있습니다.

### 자격 증명 및 페르소나

각 프로세스는 시스템에서 자신의 권한을 **식별하는 자격 증명**을 보유합니다. 각 프로세스에는 기본 `uid`와 기본 `gid`가 하나씩 있으며(여러 그룹에 속할 수는 있음),\
바이너리에 `setuid/setgid` 비트가 설정되어 있으면 사용자 ID와 그룹 ID를 변경할 수도 있습니다.\
새 `uid/gid`를 **설정하는** 함수는 여러 가지가 있습니다.

시스템 호출 **`persona`**는 **대체** 자격 증명 집합을 제공합니다. 페르소나를 채택하면 해당 페르소나의 uid, gid 및 그룹 멤버십을 **한 번에** 적용합니다. [**소스 코드**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)에서 다음 구조체를 확인할 수 있습니다:

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
2. **스레드 생성:** `pthread_create()` 함수는 새 스레드를 생성하는 데 사용됩니다. 내부적으로 이 함수는 XNU 커널(macOS의 기반이 되는 커널)에 특화된 저수준 시스템 호출인 `bsdthread_create()`를 호출합니다. 이 시스템 호출은 스케줄링 정책과 스택 크기 등 스레드 동작을 지정하는 `pthread_attr`(속성)에서 파생된 여러 플래그를 받습니다.
   - **기본 스택 크기:** 새 스레드의 기본 스택 크기는 512 KB로, 일반적인 작업에 충분하지만 더 많은 공간이나 더 적은 공간이 필요하면 스레드 속성을 통해 조정할 수 있습니다.
3. **스레드 초기화:** `__pthread_init()` 함수는 스레드 설정 과정에서 중요한 역할을 하며, `env[]` 인수를 사용해 스택 위치와 크기 등의 세부 정보가 포함될 수 있는 환경 변수를 분석합니다.

#### macOS에서 스레드 종료

1. **스레드 종료:** 일반적으로 `pthread_exit()`를 호출해 스레드를 종료합니다. 이 함수는 스레드를 정상적으로 종료하고 필요한 정리 작업을 수행하며, 대기 중인 스레드에 반환값을 전달할 수 있게 합니다.
2. **스레드 정리:** `pthread_exit()`를 호출하면 `pthread_terminate()` 함수가 실행되어 관련된 모든 스레드 구조체를 제거합니다. 이 함수는 Mach 스레드 포트(Mach는 XNU 커널의 통신 하위 시스템)를 해제하고, 스레드와 연결된 커널 수준 구조체를 제거하는 시스템 호출인 `bsdthread_terminate`를 호출합니다.

#### 동기화 메커니즘

공유 리소스에 대한 접근을 관리하고 경쟁 상태를 방지하기 위해 macOS는 여러 동기화 기본 요소를 제공합니다. 이러한 요소는 데이터 무결성과 시스템 안정성을 보장하는 데 필수적입니다.

1. **뮤텍스:**
   - **일반 뮤텍스 (시그니처: 0x4D555458):** 메모리 크기가 60바이트인 표준 뮤텍스입니다(뮤텍스 56바이트, 시그니처 4바이트).
   - **Fast Mutex (시그니처: 0x4d55545A):** 일반 뮤텍스와 유사하지만 더 빠른 작업을 위해 최적화되었으며, 크기도 60바이트입니다.
2. **조건 변수:**
   - 특정 조건이 충족될 때까지 대기하는 데 사용되며, 크기는 44바이트입니다(40바이트와 4바이트 시그니처).
   - **조건 변수 속성 (시그니처: 0x434e4441):** 조건 변수의 설정 속성이며, 크기는 12바이트입니다.
3. **Once 변수 (시그니처: 0x4f4e4345):**
   - 초기화 코드가 한 번만 실행되도록 보장합니다. 크기는 12바이트입니다.
4. **읽기-쓰기 잠금:**
   - 여러 독자 또는 한 명의 작성자만 동시에 접근할 수 있도록 하여 공유 데이터에 효율적으로 접근하게 합니다.
   - **읽기-쓰기 잠금 (시그니처: 0x52574c4b):** 크기는 196바이트입니다.
   - **읽기-쓰기 잠금 속성 (시그니처: 0x52574c41):** 읽기-쓰기 잠금의 속성이며, 크기는 20바이트입니다.

> [!TIP]
> 이러한 객체의 마지막 4바이트는 오버플로를 감지하는 데 사용됩니다.

### 스레드 로컬 변수 (TLV)

Mach-O 파일(macOS 실행 파일 형식)에서 **스레드 로컬 변수 (TLV)**는 멀티스레드 애플리케이션에서 **각 스레드별로** 다른 변수를 선언하는 데 사용됩니다. 이를 통해 각 스레드는 변수의 별도 인스턴스를 가지므로, 뮤텍스와 같은 명시적 동기화 메커니즘 없이도 충돌을 방지하고 데이터 무결성을 유지할 수 있습니다.

C 및 관련 언어에서는 **`__thread`** 키워드를 사용해 스레드 로컬 변수를 선언할 수 있습니다. 예시에서는 다음과 같이 동작합니다:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

이 코드 조각은 `tlv_var`를 스레드 로컬 변수로 정의합니다. 이 코드를 실행하는 각 스레드는 자체 `tlv_var`를 가지며, 한 스레드에서 `tlv_var`를 변경해도 다른 스레드의 `tlv_var`에는 영향을 주지 않습니다.

Mach-O 바이너리에서 스레드 로컬 변수 관련 데이터는 특정 섹션에 구성됩니다.

- **`__DATA.__thread_vars`**: 스레드 로컬 변수의 유형이나 초기화 상태와 같은 메타데이터를 포함합니다.
- **`__DATA.__thread_bss`**: 명시적으로 초기화되지 않은 스레드 로컬 변수에 사용됩니다. 0으로 초기화되는 데이터를 위해 할당된 메모리 영역의 일부입니다.

Mach-O는 스레드가 종료될 때 스레드 로컬 변수를 관리하는 **`tlv_atexit`**이라는 전용 API도 제공합니다. 이 API를 사용하면 스레드가 종료될 때 스레드 로컬 데이터를 정리하는 특수 함수인 **소멸자(destructor)를 등록**할 수 있습니다.

### 스레드 우선순위

스레드 우선순위를 이해하려면 운영체제가 어떤 스레드를 언제 실행할지 결정하는 방식을 살펴봐야 합니다. 이 결정은 각 스레드에 할당된 우선순위 수준의 영향을 받습니다. macOS 및 Unix 계열 시스템에서는 `nice`, `renice`, Quality of Service(QoS) 클래스와 같은 개념을 사용해 이를 처리합니다.

#### Nice와 Renice

1. **Nice:**
   - 프로세스의 `nice` 값은 우선순위에 영향을 주는 숫자입니다. 모든 프로세스는 -20(가장 높은 우선순위)부터 19(가장 낮은 우선순위)까지의 `nice` 값을 가집니다. 프로세스가 생성될 때의 기본 `nice` 값은 일반적으로 0입니다.
   - `nice` 값이 낮을수록(-20에 가까울수록) 프로세스가 더 "이기적"으로 동작해, `nice` 값이 더 높은 다른 프로세스보다 더 많은 CPU 시간을 사용합니다.
2. **Renice:**
   - `renice`는 이미 실행 중인 프로세스의 `nice` 값을 변경하는 명령어입니다. 새로운 `nice` 값에 따라 CPU 시간 할당을 늘리거나 줄여 프로세스 우선순위를 동적으로 조정할 수 있습니다.
   - 예를 들어, 프로세스에 일시적으로 더 많은 CPU 리소스가 필요하다면 `renice`를 사용해 `nice` 값을 낮출 수 있습니다.

#### Quality of Service(QoS) 클래스

QoS 클래스는 특히 **Grand Central Dispatch(GCD)**를 지원하는 macOS와 같은 시스템에서 스레드 우선순위를 처리하는 보다 현대적인 방식입니다. QoS 클래스를 사용하면 개발자가 작업의 중요도나 긴급도에 따라 작업을 여러 수준으로 **분류**할 수 있습니다. macOS는 이러한 QoS 클래스를 기반으로 스레드 우선순위를 자동으로 관리합니다.

1. **User Interactive:**
   - 현재 사용자와 상호작용하거나 원활한 사용자 경험을 위해 즉각적인 결과가 필요한 작업에 사용됩니다. 인터페이스의 반응성을 유지하기 위해 애니메이션이나 이벤트 처리 같은 작업에 가장 높은 우선순위를 부여합니다.
2. **User Initiated:**
   - 문서 열기나 계산이 필요한 버튼 클릭처럼 사용자가 시작하고 즉각적인 결과를 기대하는 작업에 사용됩니다. 우선순위는 높지만 User Interactive보다는 낮습니다.
3. **Utility:**
   - 파일 다운로드나 데이터 가져오기처럼 오래 실행되며 일반적으로 진행률 표시기를 보여주는 작업에 사용됩니다. 사용자 시작 작업보다 우선순위가 낮으며 즉시 완료될 필요가 없습니다.
4. **Background:**
   - 백그라운드에서 실행되고 사용자에게 보이지 않는 작업에 사용됩니다. 색인 생성, 동기화, 백업 등이 이에 해당합니다. 우선순위가 가장 낮고 시스템 성능에 미치는 영향도 최소화됩니다.

QoS 클래스를 사용하면 개발자는 정확한 우선순위 숫자를 직접 관리할 필요 없이 작업의 특성에 집중할 수 있으며, 시스템이 그에 맞춰 CPU 리소스를 최적화합니다.

또한 스케줄러가 고려할 스케줄링 매개변수 집합을 지정하는 여러 **스레드 스케줄링 정책**이 있습니다. `thread_policy_[set/get]`을 사용해 이를 설정할 수 있습니다. 이는 race condition 공격에 유용할 수 있습니다.

## macOS 프로세스 악용

macOS는 **프로세스가 상호작용하고, 통신하고, 데이터를 공유할 수 있는** 다양한 메커니즘을 제공합니다. 이러한 메커니즘은 정상적인 시스템 작동에 필수적이지만, 공격자는 이를 악용해 injection, 코드 실행 또는 데이터 접근을 수행할 수 있습니다.

### Library Injection

Library Injection은 공격자가 **프로세스에 악성 라이브러리를 로드하도록 강제하는** 기법입니다. 삽입된 라이브러리는 대상 프로세스의 컨텍스트에서 실행되므로, 공격자는 해당 프로세스와 동일한 권한과 접근 권한을 얻게 됩니다.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking은 소프트웨어 코드 내부의 **함수 호출**이나 메시지를 가로채는 기법입니다. 공격자는 함수를 후킹해 프로세스의 **동작을 변경**하거나, 민감한 데이터를 관찰하거나, 실행 흐름을 제어할 수도 있습니다.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

이 페이지에서는 ARM64 unwind 메타데이터, arm64e PAC 제약 조건, 합성 호출 체인을 다룹니다.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication(IPC)은 서로 다른 프로세스가 **데이터를 공유하고 교환하는** 여러 방법을 가리킵니다. IPC는 많은 정상적인 애플리케이션에 필수적이지만, 프로세스 격리를 우회하거나 민감한 정보를 leak하거나 권한이 없는 작업을 수행하는 데 악용될 수도 있습니다.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

특정 환경 변수를 사용해 실행되는 Electron 애플리케이션은 process injection에 취약할 수 있습니다.


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

플래그 `--load-extension` 및 `--use-fake-ui-for-media-stream`을 사용하면 **브라우저 내 중간자 공격(man in the browser attack)**을 수행해 키 입력, 트래픽, 쿠키를 탈취하거나 페이지에 스크립트를 삽입할 수 있습니다.


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB 파일은 애플리케이션 내 **사용자 인터페이스(UI) 요소와 그 상호작용을 정의**합니다. 하지만 NIB 파일은 **임의의 명령을 실행할 수 있으며**, **NIB 파일이 수정되더라도 Gatekeeper는 이미 실행된 애플리케이션이 다시 실행되는 것을 막지 않습니다**. 따라서 NIB 파일을 이용해 임의의 프로그램이 임의의 명령을 실행하도록 할 수 있습니다.


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, **`JDK_JAVA_OPTIONS`**를 통해 JVM 옵션을 삽입하고 애플리케이션이 시작되기 전에 Java 또는 native agent를 로드할 수 있습니다.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**는 `--require`(파일) 또는 `--import data:text/javascript,…`(파일리스, Node ≥ 20.6)를 통해 공격자의 JavaScript를 사전 로드합니다. **`NODE_REPL_EXTERNAL_MODULE`**은 대화형 REPL에 모듈을 로드하며, **`ELECTRON_RUN_AS_NODE`**는 Electron 바이너리에서 이 기능을 다시 활성화합니다.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

**`DOTNET_STARTUP_HOOKS`**를 통해 `Main` 실행 전에 .NET 애플리케이션에 코드를 삽입하거나, 필요한 전제 조건이 충족된 경우 .NET 디버깅 기능을 악용할 수 있습니다.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

비대화형 Bash는 **`BASH_ENV`**를 읽고, 대화형 POSIX 셸은 **`ENV`**를 읽습니다. zsh는 **`$ZDOTDIR/.zshenv`**를 읽으며, fish는 **`XDG_CONFIG_HOME`** 또는 **`XDG_DATA_DIRS`** 아래의 설정 파일을 읽습니다. 각 셸은 의도된 명령을 실행하기 전에 제어 가능한 시작 파일을 실행할 수 있습니다. 또한 xtrace가 활성화되어 있으면(예: 상속된 **`SHELLOPTS=xtrace`**) Bash는 **`PS4`**에 지정된 명령 치환을 실행합니다.

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s`를 실행하면 셸은 표준 입력에서 프로그램을 읽습니다. 따라서 신뢰할 수 없는 구조화된 문서를 파싱하지 않고 자식 프로세스의 stdin으로 복사하는 downloader는 문서 전체를 셸 소스로 전달하게 됩니다. 실제로 관찰된 한 loader는 공개 iCalendar 파일을 익명 파이프를 통해 한 줄씩 전달했습니다. 캘린더 메타데이터는 명령으로 실행되지 않았지만, zsh는 `DESCRIPTION:` 뒤에 배치된 실행 가능한 줄에 도달할 때까지 계속 실행했습니다. 해당 줄은 다음 애플리케이션 번들을 다운로드하고 실행했습니다. 전달 매체의 예상 콘텐츠 유형과 신뢰할 수 있는 호스팅도 이 동작을 안전하게 만들지는 못했습니다. 위험한 경계는 해당 바이트를 인터프리터에 전달한 것이었습니다.<sup>[[5]](#references)</sup>

관련 단계는 [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), [macOS auto-start locations](../../macos-auto-start-locations.md)에서 다룹니다.

### PHP Injection

**`PHPRC`** 또는 **`PHP_INI_SCAN_DIR`**를 이용해 제어 가능한 PHP 설정을 로드할 수 있으며, 설정의 **`auto_prepend_file`**은 대상 스크립트보다 먼저 실행됩니다.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

독립 실행형 Lua 인터프리터는 대상 스크립트를 처리하기 전에 **`LUA_INIT`**(또는 버전별 변형)에 지정된 코드나 `@file`을 실행합니다.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** 및 **`R_PROFILE`**은 R 코드가 포함된 시작 프로파일의 경로를 변경합니다. 또는 **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**와 R 라이브러리 경로를 이용해 설치된 패키지를 자동 로드할 수 있습니다.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**는 `config/startup.jl`이 자동 실행되는 depot의 경로를 변경합니다.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** 또는 **`ERL_ZFLAGS`**를 사용하면 payload 파일 없이 Erlang VM의 **`-eval`** 표현식을 삽입할 수 있습니다. Elixir 워크로드도 일반적으로 같은 VM을 시작합니다.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 및 **`OCTAVE_VERSION_INITFILE`**은 Octave 시작 스크립트의 경로를 변경합니다.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh`는 크로스 플랫폼 .NET 앱이므로 여러 환경 변수를 통해 명령 실행 전에 코드를 실행할 수 있습니다. **`XDG_CONFIG_HOME`**은 시작 시 실행되는 프로파일 스크립트의 경로를 변경하고, **`PSModulePath`**는 모듈 자동 로드를 가로챕니다(심어 둔 `.psm1`은 가져오는 시점에 실행되며 기본 제공 cmdlet을 대체할 수 있음). 또한 .NET의 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 및 **`DOTNET_STARTUP_HOOKS`** 변수는 `Main` 실행 전에 공격자 코드를 프로세스에 로드합니다.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

다음에서 Perl 스크립트가 임의의 코드를 실행하도록 하는 여러 방법을 확인하세요.


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

ruby 환경 변수(**`RUBYOPT`**, **`RUBYLIB`**)를 악용해 임의의 스크립트가 임의의 코드를 실행하도록 할 수도 있습니다.


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`**와 **`BROWSER`** 표준 라이브러리 체인을 이용하면 warning-filter를 파싱하는 동안 명령을 실행할 수 있습니다. 파일을 사용하는 대안으로 **`PYTHONPATH`**에 `sitecustomize.py`를 두면 일반적인 `site` 초기화 과정에서 대상 스크립트보다 먼저 해당 파일을 가져옵니다. **`PYTHONBREAKPOINT`**는 코드가 `breakpoint()`에 도달할 때 지정된 callable/module을 실행합니다. **`PYTHONSTARTUP`** 같은 대화형 전용 변수는 적용 범위가 더 제한적입니다.

**`pyinstaller`**로 컴파일된 실행 파일은 내장 Python을 사용해 실행되더라도 이러한 환경 변수를 사용하지 않는다는 점에 유의하세요.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**(및 대체 변수인 `EXINIT`)은 일반적인 시작 과정에서 Ex 명령으로 실행됩니다. 따라서 피해자가 제어된 환경에서 Vim/Neovim을 열면 `:!cmd` / `:call system(...)`을 통해 코드 실행이 가능합니다.

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

별도로, Homebrew는 Python을 `/opt/homebrew` 아래에 설치하는 경우가 많으며, 로컬 `admin` 그룹의 구성원은 launcher를 교체할 수 있습니다. 이는 환경 변수 injection이 아니라 쓰기 가능한 바이너리 하이재킹이므로, 악용 가능하다고 판단하기 전에 소유권과 ACL을 확인하세요.


## 탐지

### Shield

[**Shield**](https://github.com/theevilbit/Shield)는 process injection을 탐지하고 차단하는 오픈 소스 **EndpointSecurity** 기반 애플리케이션입니다. Endpoint Security를 통해 어떤 신호를 관찰할 수 있는지 보여주는 좋은 참고 자료이며, 다음 항목에 대해 경고합니다.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- 프로세스 exec 시 **injection 환경 변수**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH`, `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** 호출 — 한 프로세스가 다른 프로세스의 task port를 요청하는 것으로, 해당 프로세스에 injection을 수행하기 위한 전제 조건입니다.
- **Electron 디버깅 인자** — `--inspect`, `--inspect-brk`, `--remote-debugging-port`. 이 인자들은 Electron 앱을 디버그 모드로 시작해 누구나 연결하여 코드를 실행할 수 있도록 합니다.<sup>[[3]](#references)</sup>
- **권한 수준이 다른 사용자 간의 symlink/hardlink 생성** — 일반 사용자로 링크를 만들고 이를 권한이 필요한 위치를 가리키도록 하는 전형적인 수법입니다. **symlink는 경고할 수 있지만 차단할 수는 없습니다**. EndpointSecurity는 링크가 생성되기 전에 링크 대상 경로를 제공하지 않습니다.

### 다른 프로세스가 수행한 호출

[**이 블로그 게시물**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)에서는 **`task_name_for_pid`** 함수를 사용해 **프로세스에 코드를 삽입하는 다른 프로세스**에 대한 정보를 얻고, 이어서 그 프로세스에 대한 정보를 가져오는 방법을 확인할 수 있습니다.<sup>[[4]](#references)</sup>

이 함수를 호출하려면 해당 프로세스를 실행하는 사용자와 **동일한 uid**를 사용하거나 **root**여야 합니다(이 함수는 프로세스에 대한 정보를 반환할 뿐, 코드를 삽입하는 방법을 제공하지는 않습니다).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — 오픈 소스 macOS process-injection 탐지 (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity 프레임워크](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron 앱이 비밀을 기밀로 보관할 수 없는 이유: --inspect 옵션](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task 수정 탐지](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer의 새 버전, 암호화폐 애호가와 개발자를 표적으로 삼다](https://securelist.com/macsync-new-version/121383/)
