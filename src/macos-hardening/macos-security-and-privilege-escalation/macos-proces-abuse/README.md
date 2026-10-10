# macOS 프로세스 악용

{{#include ../../../banners/hacktricks-training.md}}

## 프로세스 기본 정보

프로세스는 실행 중인 실행 파일의 인스턴스입니다. 하지만 프로세스가 코드를 실행하는 것은 아니며, 코드는 스레드가 실행합니다. 따라서 **프로세스는 스레드가 실행되는 컨테이너일 뿐이며**, 메모리, 디스크립터, 포트, 권한 등을 제공합니다.

전통적으로 PID 1을 제외한 프로세스는 **`fork`**를 호출해 다른 프로세스 내에서 시작되었습니다. `fork`는 현재 프로세스의 정확한 복사본을 만들고, 이어서 **자식 프로세스**가 일반적으로 **`execve`**를 호출해 새 실행 파일을 로드하고 실행했습니다. 이후 메모리 복사 없이 이 과정을 더 빠르게 수행하기 위해 **`vfork`**가 도입되었습니다.\
그다음 **`vfork`**와 **`execve`**를 한 번의 호출로 결합하고 플래그를 받는 **`posix_spawn`**이 도입되었습니다.

- `POSIX_SPAWN_RESETIDS`: 유효 ID를 실제 ID로 재설정
- `POSIX_SPAWN_SETPGROUP`: 프로세스 그룹 소속 설정
- `POSUX_SPAWN_SETSIGDEF`: 신호 기본 동작 설정
- `POSIX_SPAWN_SETSIGMASK`: 신호 마스크 설정
- `POSIX_SPAWN_SETEXEC`: 같은 프로세스에서 exec 실행 (옵션이 더 많은 `execve`와 유사)
- `POSIX_SPAWN_START_SUSPENDED`: 일시 중단된 상태로 시작
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR 없이 시작
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc의 Nano allocator 사용
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 데이터 세그먼트에서 `rwx` 허용
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 기본적으로 exec(2) 시 모든 파일 디스크립션 닫기
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR 슬라이드의 상위 비트를 무작위화

또한 `posix_spawn`은 생성되는 프로세스의 동작을 제어하는 **`posix_spawnattr`** 설정과 파일 디스크립터를 수정하는 **`posix_spawn_file_actions`** 항목을 받습니다.

프로세스가 종료되면 신호 `SIGCHLD`를 통해 **종료 코드를 부모 프로세스에 전송**합니다 (부모가 이미 종료된 경우 새 부모는 PID 1입니다). 부모는 `wait4()` 또는 `waitid()`를 호출해 이 값을 받아야 합니다. 그때까지 자식은 목록에는 표시되지만 리소스를 소비하지 않는 좀비 상태로 남습니다.

### PID

PID(프로세스 식별자)는 고유한 프로세스를 식별합니다. XNU에서 **PID**는 **64비트**이며, 값이 단조 증가하고 **절대 순환하지 않습니다** (악용 방지 목적).

### 프로세스 그룹, 세션 및 코얼리션

**프로세스**를 **그룹**에 넣으면 프로세스를 더 쉽게 관리할 수 있습니다. 예를 들어 셸 스크립트의 명령은 같은 프로세스 그룹에 속하므로 `kill` 등을 사용해 **함께 신호를 보낼 수 있습니다**.\
프로세스를 **세션으로 그룹화**할 수도 있습니다. 프로세스가 세션을 시작하면 (`setsid(2)`), 자체 세션을 시작하지 않는 한 자식 프로세스는 해당 세션에 포함됩니다.

코얼리션은 Darwin에서 프로세스를 그룹화하는 또 다른 방법입니다. 코얼리션에 참여한 프로세스는 풀 리소스에 접근하고, 원장을 공유하거나 Jetsam의 대상이 될 수 있습니다. 코얼리션에는 Leader, XPC service, Extension 등 여러 역할이 있습니다.

### 자격 증명 및 페르소나

각 프로세스는 시스템 내 권한을 **식별하는 자격 증명**을 보유합니다. 각 프로세스에는 기본 `uid`와 기본 `gid`가 하나씩 있으며 (여러 그룹에 속할 수는 있습니다).\
바이너리에 `setuid/setgid` 비트가 설정되어 있으면 사용자 ID와 그룹 ID를 변경할 수도 있습니다.\
새 `uid/gid`를 **설정하는** 함수는 여러 가지가 있습니다.

시스템 호출 **`persona`**는 **대체** **자격 증명** 집합을 제공합니다. 페르소나를 채택하면 해당 페르소나의 uid, gid 및 그룹 멤버십이 **한꺼번에** 적용됩니다. [**소스 코드**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)에서 다음 구조체를 확인할 수 있습니다:

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

## Threads 기본 정보

1. **POSIX Threads (pthreads):** macOS는 C/C++용 표준 threading API의 일부인 POSIX threads(`pthreads`)를 지원합니다. macOS의 pthreads 구현은 공개적으로 제공되는 `libpthread` 프로젝트에서 가져온 `/usr/lib/system/libsystem_pthread.dylib`에 있습니다. 이 라이브러리는 threads를 생성하고 관리하는 데 필요한 함수를 제공합니다.
2. **Threads 생성:** `pthread_create()` 함수는 새 threads를 생성하는 데 사용됩니다. 내부적으로 이 함수는 XNU kernel(macOS의 기반 kernel)에만 있는 저수준 system call인 `bsdthread_create()`를 호출합니다. 이 system call은 scheduling 정책 및 stack 크기를 포함한 thread 동작을 지정하는 `pthread_attr`(속성)에서 파생된 여러 플래그를 받습니다.
   - **기본 Stack 크기:** 새 threads의 기본 stack 크기는 512 KB입니다. 일반적인 작업에 충분한 크기이며, 더 많거나 적은 공간이 필요한 경우 thread 속성으로 조정할 수 있습니다.
3. **Thread 초기화:** `__pthread_init()` 함수는 thread 설정 과정에서 중요하며, `env[]` 인수를 사용해 stack의 위치와 크기 등의 정보를 포함할 수 있는 environment variables를 파싱합니다.

#### macOS의 Thread 종료

1. **Threads 종료:** 일반적으로 `pthread_exit()`를 호출해 threads를 종료합니다. 이 함수는 thread를 정상적으로 종료하고 필요한 정리 작업을 수행하며, join하는 thread에 반환값을 전달할 수 있도록 합니다.
2. **Thread 정리:** `pthread_exit()`를 호출하면 모든 관련 thread 구조체의 제거를 처리하는 `pthread_terminate()` 함수가 호출됩니다. 이 함수는 Mach thread ports(Mach는 XNU kernel의 통신 하위 시스템)를 할당 해제하고, thread와 연결된 kernel 수준 구조체를 제거하는 syscall인 `bsdthread_terminate`를 호출합니다.

#### 동기화 메커니즘

macOS는 공유 리소스에 대한 접근을 관리하고 race condition을 방지하기 위해 여러 동기화 primitive를 제공합니다. 이는 데이터 무결성과 시스템 안정성을 보장하는 데 필요한 multi-threading 환경에서 중요합니다.

1. **Mutexes:**
   - **일반 Mutex (Signature: 0x4D555458):** 메모리 사용량이 60 bytes인 표준 mutex(56 bytes는 mutex, 4 bytes는 signature).
   - **Fast Mutex (Signature: 0x4d55545A):** 일반 mutex와 유사하지만 더 빠른 작업을 위해 최적화되어 있으며, 크기는 60 bytes입니다.
2. **Condition Variables:**
   - 특정 조건이 발생할 때까지 기다리는 데 사용되며, 크기는 44 bytes(40 bytes와 4-byte signature)입니다.
   - **Condition Variable Attributes (Signature: 0x434e4441):** condition variables의 설정 속성이며, 크기는 12 bytes입니다.
3. **Once Variable (Signature: 0x4f4e4345):**
   - 초기화 코드가 한 번만 실행되도록 보장합니다. 크기는 12 bytes입니다.
4. **Read-Write Locks:**
   - 여러 reader 또는 한 writer가 한 번에 접근할 수 있도록 하여 공유 데이터에 효율적으로 접근할 수 있게 합니다.
   - **Read Write Lock (Signature: 0x52574c4b):** 크기는 196 bytes입니다.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** read-write locks의 속성이며, 크기는 20 bytes입니다.

> [!TIP]
> 해당 객체의 마지막 4 bytes는 overflow를 감지하는 데 사용됩니다.

### Thread Local Variables (TLV)

Mach-O 파일(macOS 실행 파일 형식)의 **Thread Local Variables (TLV)**는 multi-threaded 애플리케이션에서 **각 thread마다** 별도로 사용되는 변수를 선언하는 데 쓰입니다. 따라서 각 thread는 변수의 독립된 인스턴스를 가지며, mutex 같은 명시적인 동기화 메커니즘 없이도 충돌을 방지하고 데이터 무결성을 유지할 수 있습니다.

C 및 관련 언어에서는 **`__thread`** 키워드를 사용해 thread-local 변수를 선언할 수 있습니다. 다음 예제에서는 이렇게 동작합니다:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

이 snippet은 `tlv_var`를 thread-local variable로 정의합니다. 이 코드를 실행하는 각 thread는 자체 `tlv_var`를 가지며, 한 thread에서 `tlv_var`를 변경해도 다른 thread의 `tlv_var`에는 영향을 주지 않습니다.

Mach-O binary에서 thread local variables 관련 데이터는 특정 section에 구성됩니다.

- **`__DATA.__thread_vars`**: thread-local variables의 타입과 초기화 상태 같은 metadata를 포함합니다.
- **`__DATA.__thread_bss`**: 명시적으로 초기화되지 않은 thread-local variables에 사용됩니다. 0으로 초기화되는 데이터를 위해 확보된 메모리 영역입니다.

Mach-O는 thread가 종료될 때 thread-local variables를 관리하는 `tlv_atexit`이라는 특정 API도 제공합니다. 이 API를 사용하면 thread가 종료될 때 thread-local data를 정리하는 특수 함수인 **destructors를 등록**할 수 있습니다.

### Threading Priorities

thread priorities를 이해하려면 운영체제가 어떤 thread를 언제 실행할지 결정하는 방식을 살펴봐야 합니다. 이 결정은 각 thread에 할당된 priority level의 영향을 받습니다. macOS 및 Unix 계열 시스템에서는 `nice`, `renice`, Quality of Service (QoS) classes 같은 개념을 사용합니다.

#### Nice and Renice

1. **Nice:**
   - process의 `nice` 값은 priority에 영향을 주는 숫자입니다. 모든 process는 -20 (가장 높은 priority)부터 19 (가장 낮은 priority)까지의 nice 값을 가집니다. process가 생성될 때의 기본 nice 값은 일반적으로 0입니다.
   - nice 값이 낮을수록 (-20에 가까울수록) process는 더 "이기적"이 되어, nice 값이 더 높은 다른 process보다 더 많은 CPU 시간을 할당받습니다.
2. **Renice:**
   - `renice`는 이미 실행 중인 process의 nice 값을 변경하는 명령어입니다. 새 nice 값에 따라 CPU 시간 할당을 늘리거나 줄여 process priority를 동적으로 조정할 수 있습니다.
   - 예를 들어, process에 일시적으로 더 많은 CPU 리소스가 필요한 경우 `renice`를 사용해 nice 값을 낮출 수 있습니다.

#### Quality of Service (QoS) Classes

QoS classes는 특히 **Grand Central Dispatch (GCD)**를 지원하는 macOS 같은 시스템에서 thread priorities를 처리하는 보다 현대적인 방식입니다. QoS classes를 사용하면 개발자가 작업의 중요도나 긴급도에 따라 여러 level로 **분류**할 수 있습니다. macOS는 이러한 QoS classes를 기반으로 thread priority를 자동으로 관리합니다.

1. **User Interactive:**
   - 현재 사용자와 상호작용 중이거나 좋은 사용자 경험을 위해 즉각적인 결과가 필요한 작업에 해당합니다. interface의 반응성을 유지하기 위해 가장 높은 priority가 부여됩니다 (예: animation 또는 event handling).
2. **User Initiated:**
   - 문서 열기나 계산이 필요한 버튼 클릭처럼 사용자가 시작하고 즉각적인 결과를 기대하는 작업입니다. priority가 높지만 User Interactive보다는 낮습니다.
3. **Utility:**
   - 장시간 실행되며 일반적으로 진행률 표시기를 보여주는 작업입니다 (예: 파일 다운로드, 데이터 가져오기). User Initiated 작업보다 priority가 낮으며 즉시 완료할 필요는 없습니다.
4. **Background:**
   - 백그라운드에서 실행되며 사용자에게 보이지 않는 작업에 해당합니다. indexing, syncing, backup 같은 작업이 여기에 포함될 수 있습니다. priority가 가장 낮고 시스템 성능에 미치는 영향도 최소화됩니다.

QoS classes를 사용하면 개발자는 정확한 priority 숫자를 관리하는 대신 작업의 성격에 집중할 수 있으며, 시스템이 그에 따라 CPU 리소스를 최적화합니다.

또한 scheduler가 고려할 scheduling parameters 집합을 지정하는 여러 **thread scheduling policies**가 있습니다. `thread_policy_[set/get]`을 사용해 설정할 수 있으며, race condition attacks에 유용할 수 있습니다.

## macOS Process Abuse

macOS는 **process 간 상호작용, 통신 및 데이터 공유**를 위한 여러 메커니즘을 제공합니다. 이러한 메커니즘은 정상적인 시스템 작동에 필수적이지만, 공격자가 이를 injection, code execution 또는 data access에 악용할 수 있습니다.

### Library Injection

Library Injection은 공격자가 **process에 악성 library를 강제로 로드하는** 기법입니다. injection된 library는 대상 process의 context에서 실행되므로, 공격자는 해당 process와 동일한 permissions 및 access를 얻게 됩니다.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking은 software code 내의 **function calls** 또는 message를 가로채는 기법입니다. 공격자는 function을 hook하여 process의 **동작을 변경**하거나, 민감한 데이터를 관찰하거나, 실행 흐름을 제어할 수도 있습니다.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC)은 별도의 process들이 **데이터를 공유하고 교환하는** 여러 방법을 가리킵니다. IPC는 많은 정상적인 application에 필수적이지만, process isolation을 무력화하거나, 민감한 정보를 leak하거나, 권한이 없는 작업을 수행하는 데 악용될 수도 있습니다.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

특정 env variables로 실행되는 Electron applications는 process injection에 취약할 수 있습니다.


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` 및 `--use-fake-ui-for-media-stream` flags를 사용해 **man in the browser attack**을 수행할 수 있습니다. 이를 통해 keystrokes, traffic, cookies를 탈취하거나 페이지에 scripts를 inject할 수 있습니다.


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files는 application 내의 **user interface (UI) elements**와 상호작용을 **정의**합니다. 하지만 **임의의 commands를 실행할 수 있으며**, **NIB file이 수정된 경우 Gatekeeper는 이미 실행된 application이 다시 실행되는 것을 막지 않습니다**. 따라서 임의의 programs가 임의의 commands를 실행하도록 하는 데 사용할 수 있습니다.


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** 또는 **`JDK_JAVA_OPTIONS`**를 통해 JVM options를 inject하고 application이 시작되기 전에 Java 또는 native agent를 로드할 수 있습니다.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**는 `--require` (file) 또는 `--import data:text/javascript,…` (fileless, Node ≥ 20.6)를 통해 공격자의 JavaScript를 preload합니다. **`NODE_REPL_EXTERNAL_MODULE`**은 interactive REPL에 module을 로드하며, **`ELECTRON_RUN_AS_NODE`**는 Electron binaries에서 이러한 기능을 다시 활성화합니다.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` 실행 전에 **`DOTNET_STARTUP_HOOKS`**를 사용하거나, 전제 조건이 충족된 경우 .NET debugging 기능을 악용해 .NET applications에 code를 inject할 수 있습니다.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash는 **`BASH_ENV`**를 읽습니다. interactive POSIX shells는 **`ENV`**를 읽고, zsh는 **`$ZDOTDIR/.zshenv`**를 읽으며, fish는 **`XDG_CONFIG_HOME`** 또는 **`XDG_DATA_DIRS`** 아래의 configuration을 읽습니다. 각각은 의도한 command보다 먼저 제어된 startup file을 실행할 수 있습니다. 또한 xtrace가 활성화되면 (예: **`SHELLOPTS=xtrace`**가 상속된 경우) Bash는 **`PS4`**에 지정된 command substitution을 실행합니다.

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** 또는 **`PHP_INI_SCAN_DIR`**를 사용하면 제어된 PHP configuration을 로드할 수 있으며, 이 configuration의 **`auto_prepend_file`**은 대상 script보다 먼저 실행됩니다.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

standalone Lua interpreter는 대상 script를 처리하기 전에 **`LUA_INIT`** (또는 version-specific variant)에 지정된 code 또는 `@file`을 실행합니다.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** 및 **`R_PROFILE`**은 R code가 포함된 startup profiles를 다른 경로로 지정합니다. 또는 **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**와 R library path를 사용해 설치된 package를 자동으로 로드할 수 있습니다.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**는 `config/startup.jl`이 자동으로 실행되는 depot의 경로를 변경합니다.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** 또는 **`ERL_ZFLAGS`**를 사용하면 payload file 없이 Erlang VM **`-eval`** expression을 inject할 수 있습니다. Elixir workloads도 일반적으로 동일한 VM을 시작합니다.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 및 **`OCTAVE_VERSION_INITFILE`**은 Octave startup scripts의 경로를 변경합니다.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh`는 cross-platform .NET app이므로 여러 environment variables를 통해 command 실행 전에 code를 실행할 수 있습니다. **`XDG_CONFIG_HOME`**은 시작 시 실행되는 profile scripts의 경로를 변경하고, **`PSModulePath`**는 module auto-loading을 hijack합니다 (심어 둔 `.psm1`은 import 시 실행되며 built-in cmdlets를 shadow할 수 있습니다). 또한 .NET의 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 및 **`DOTNET_STARTUP_HOOKS`** variables는 `Main` 전에 process에 공격자 code를 로드합니다.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script가 다음 경로에서 임의의 code를 실행하도록 하는 여러 방법을 확인하세요.


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**)를 악용해 임의의 scripts가 임의의 code를 실행하도록 할 수도 있습니다.


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`**와 **`BROWSER`** standard-library chain은 warning-filter parsing 중 command를 실행할 수 있습니다. file을 사용하는 대안으로, **`PYTHONPATH`**에 `sitecustomize.py`를 배치하면 일반적인 `site` initialization 과정에서 대상 script보다 먼저 import됩니다. **`PYTHONBREAKPOINT`**는 code가 `breakpoint()`에 도달할 때 지정된 callable/module을 실행합니다. **`PYTHONSTARTUP`** 같은 interactive 전용 variables는 적용 범위가 더 제한적입니다.

**`pyinstaller`**로 compile된 executables는 embedded Python으로 실행되더라도 이러한 environmental variables를 사용하지 않습니다.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (및 fallback인 `EXINIT`)은 정상적인 시작 과정에서 Ex commands로 실행되므로, 피해자가 제어된 environment에서 Vim/Neovim을 열면 `:!cmd` / `:call system(...)`으로 code execution이 가능합니다.

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

이와 별개로, Homebrew는 흔히 Python을 `/opt/homebrew` 아래에 설치하며, 이 경로에서는 로컬 `admin` group의 구성원이 launcher를 교체할 수 있습니다. 이는 environment-variable injection이 아닌 writable-binary hijack입니다. 취약하다고 판단하기 전에 ownership과 ACLs를 확인하세요.


## 탐지

### Shield

[**Shield**](https://github.com/theevilbit/Shield)는 process injection을 탐지하고 차단하는 open-source **EndpointSecurity** 기반 application입니다. Endpoint Security를 통해 어떤 signals를 관찰할 수 있는지 파악하는 데 좋은 참고 자료이며, 다음 항목에 대해 alert를 표시합니다.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- process exec 시 **injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH`, `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — 다른 process의 task port를 요청하는 호출로, 해당 process에 injection을 수행하기 위한 전제 조건입니다.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk`, `--remote-debugging-port`. 이 arguments는 Electron app을 debug mode로 시작해 누구나 연결하여 code를 실행할 수 있게 합니다.<sup>[[3]](#references)</sup>
- **권한 수준 간 symlink/hardlink 생성** — 일반 사용자가 link를 심고 이를 권한이 필요한 경로를 가리키도록 하는 전형적인 수법입니다. **symlinks는 alert 대상으로 감지할 수 있지만 차단할 수는 없습니다**. EndpointSecurity는 link가 생성되기 전에 link destination을 노출하지 않기 때문입니다.

### 다른 process에서 이루어진 calls

[**이 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)에서 **`task_name_for_pid`** function을 사용해 process에 code를 inject하는 다른 **process에 대한 정보**를 얻고, 그 다른 process에 대한 정보를 추가로 확인하는 방법을 볼 수 있습니다.<sup>[[4]](#references)</sup>

이 function을 호출하려면 해당 process를 실행하는 사용자와 **동일한 uid**이거나 **root**여야 합니다 (또한 이 function은 process에 대한 정보를 반환할 뿐, code를 inject하는 방법을 제공하지 않습니다).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron 앱이 비밀 정보를 기밀로 저장할 수 없는 이유: --inspect 옵션](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modification 탐지](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
