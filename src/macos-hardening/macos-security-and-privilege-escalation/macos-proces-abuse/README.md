# macOS 프로세스 악용

{{#include ../../../banners/hacktricks-training.md}}

## 프로세스 기본 정보

프로세스는 실행 중인 executable의 인스턴스이지만, 프로세스는 code를 실행하지 않으며 thread가 이를 실행합니다. 따라서 **프로세스는 실행 중인 thread를 위한 단순한 컨테이너**로, memory, descriptors, ports, permissions...를 제공합니다.

전통적으로 프로세스는 **`fork`**를 호출하여 다른 프로세스 내부에서 시작되었습니다(PID 1 제외). 이 호출은 현재 프로세스의 정확한 복사본을 생성하며, 이후 **child process**는 일반적으로 **`execve`**를 호출하여 새로운 executable을 로드하고 실행합니다. 이후 memory 복사 없이 이 프로세스를 더 빠르게 만들기 위해 **`vfork`**가 도입되었습니다.\
그다음 **`posix_spawn`**이 도입되어 **`vfork`**와 **`execve`**를 한 번의 호출로 결합하고 다음 flags를 허용했습니다:

- `POSIX_SPAWN_RESETIDS`: effective ids를 real ids로 재설정
- `POSIX_SPAWN_SETPGROUP`: process group 소속 설정
- `POSUX_SPAWN_SETSIGDEF`: signal 기본 동작 설정
- `POSIX_SPAWN_SETSIGMASK`: signal mask 설정
- `POSIX_SPAWN_SETEXEC`: 동일한 프로세스에서 Exec 수행(`execve`와 유사하지만 더 많은 options 제공)
- `POSIX_SPAWN_START_SUSPENDED`: suspended 상태로 시작
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR 없이 시작
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc의 Nano allocator 사용
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments에서 `rwx` 허용
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 기본적으로 exec(2) 시 모든 file descriptions 닫기
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide의 high bits randomize

또한 `posix_spawn`은 생성된 프로세스의 측면을 제어하는 **`posix_spawnattr`** settings와 file descriptors를 수정하는 **`posix_spawn_file_actions`** entries를 허용합니다.

프로세스가 종료되면 signal `SIGCHLD`를 사용하여 **return code를 parent process에 전송**합니다(parent가 종료된 경우 새로운 parent는 PID 1입니다). Parent는 `wait4()` 또는 `waitid()`를 호출하여 이 값을 가져와야 하며, 그 일이 발생할 때까지 child는 여전히 목록에 표시되지만 resources를 소비하지 않는 zombie 상태로 유지됩니다.

### PIDs

PIDs(process identifiers)는 고유한 프로세스를 식별합니다. XNU에서 **PIDs**는 **64bits**이며 단조롭게 증가하고 **절대 wrap되지 않습니다**(abuses 방지 목적).

### Process Groups, Sessions & Coalations

**프로세스**는 처리를 더 쉽게 하기 위해 **groups**에 삽입할 수 있습니다. 예를 들어 shell script의 commands는 동일한 process group에 속하므로, kill 등을 사용하여 **함께 signal을 보낼** 수 있습니다.\
프로세스를 **sessions로 group화**하는 것도 가능합니다. 프로세스가 session(`setsid(2)`)을 시작하면, child processes가 자체 session을 시작하지 않는 한 해당 child processes는 session 내부에 배치됩니다.

Coalition은 Darwin에서 프로세스를 group화하는 또 다른 방법입니다. 프로세스가 coalition에 참여하면 pool resources에 접근하고, ledger를 공유하거나 Jetsam의 대상이 될 수 있습니다. Coalition에는 Leader, XPC service, Extension과 같은 서로 다른 roles가 있습니다.

### Credentials & Personae

각 프로세스는 시스템에서 해당 **privileges를 식별하는** **credentials**를 보유합니다. 각 프로세스에는 하나의 기본 `uid`와 하나의 기본 `gid`가 있으며(여러 groups에 속할 수는 있음),\
binary에 `setuid/setgid` bit가 설정되어 있다면 user 및 group id를 변경할 수도 있습니다.\
새로운 uids/gids를 **설정하는** 여러 functions가 있습니다.

**`persona`** syscall은 **credentials**의 **alternate** set을 제공합니다. Persona를 채택하면 해당 uid, gid 및 group memberships를 **한 번에** 사용하게 됩니다. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)에서 다음 struct를 확인할 수 있습니다:
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

1. **POSIX Threads (pthreads):** macOS는 C/C++용 표준 threading API의 일부인 POSIX threads(`pthreads`)를 지원합니다. macOS의 pthreads 구현은 공개적으로 제공되는 `libpthread` project에서 제공되며 `/usr/lib/system/libsystem_pthread.dylib`에 있습니다. 이 library는 threads를 생성하고 관리하는 데 필요한 functions를 제공합니다.
2. **Threads 생성:** `pthread_create()` function은 새로운 threads를 생성하는 데 사용됩니다. 내부적으로 이 function은 XNU kernel(macOS의 기반이 되는 kernel)에 특화된 low-level system call인 `bsdthread_create()`를 호출합니다. 이 system call은 `pthread_attr`(attributes)에서 파생된 다양한 flags를 사용하며, 여기에는 scheduling policies와 stack size 등 thread behavior를 지정하는 설정이 포함됩니다.
- **기본 Stack Size:** 새로운 threads의 기본 stack size는 512 KB입니다. 일반적인 작업에는 충분하지만, 더 많거나 적은 공간이 필요한 경우 thread attributes를 통해 조정할 수 있습니다.
3. **Thread Initialization:** `__pthread_init()` function은 thread setup 과정에서 중요하며, stack의 location과 size에 관한 세부 정보를 포함할 수 있는 environment variables를 `env[]` argument를 사용해 parsing합니다.

#### macOS에서의 Thread Termination

1. **Threads 종료:** Threads는 일반적으로 `pthread_exit()`를 호출하여 종료합니다. 이 function은 thread가 정상적으로 종료되도록 하며, 필요한 cleanup을 수행하고 thread가 joiners에 return value를 전달할 수 있도록 합니다.
2. **Thread Cleanup:** `pthread_exit()`를 호출하면 `pthread_terminate()` function이 호출되어 연결된 모든 thread structures를 제거합니다. 이 function은 Mach thread ports(Mach는 XNU kernel의 communication subsystem)를 deallocate하고, thread와 연결된 kernel-level structures를 제거하는 syscall인 `bsdthread_terminate`를 호출합니다.

#### Synchronization Mechanisms

공유 resources에 대한 access를 관리하고 race conditions를 방지하기 위해 macOS는 여러 synchronization primitives를 제공합니다. 이는 data integrity와 system stability를 보장하는 데 중요한 multi-threading environments의 핵심 요소입니다.

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** memory footprint가 60 bytes인 standard mutex입니다(56 bytes는 mutex, 4 bytes는 signature).
- **Fast Mutex (Signature: 0x4d55545A):** regular mutex와 유사하지만 더 빠른 operations에 최적화되어 있으며, 크기도 60 bytes입니다.
2. **Condition Variables:**
- 특정 conditions가 발생할 때까지 대기하는 데 사용되며, 크기는 44 bytes입니다(40 bytes와 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** condition variables의 configuration attributes이며, 크기는 12 bytes입니다.
3. **Once Variable (Signature: 0x4f4e4345):**
- initialization code가 한 번만 실행되도록 보장합니다. 크기는 12 bytes입니다.
4. **Read-Write Locks:**
- 여러 readers 또는 한 번에 하나의 writer를 허용하여 shared data에 효율적으로 access할 수 있도록 합니다.
- **Read Write Lock (Signature: 0x52574c4b):** 크기는 196 bytes입니다.
- **Read Write Lock Attributes (Signature: 0x52574c41):** read-write locks의 attributes이며, 크기는 20 bytes입니다.

> [!TIP]
> 이러한 objects의 마지막 4 bytes는 overflow를 detect하는 데 사용됩니다.

### Thread Local Variables (TLV)

Mach-O files(macOS의 executables 형식)의 context에서 **Thread Local Variables (TLV)**는 multi-threaded application에서 **각 thread**에 특화된 variables를 선언하는 데 사용됩니다. 이를 통해 각 thread가 variable의 별도 instance를 갖도록 하여, mutexes와 같은 explicit synchronization mechanisms 없이도 conflicts를 방지하고 data integrity를 유지할 수 있습니다.

C 및 관련 languages에서는 **`__thread`** keyword를 사용하여 thread-local variable을 선언할 수 있습니다. 다음은 example에서 작동하는 방식입니다:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
이 snippet은 `tlv_var`를 thread-local variable로 정의합니다. 이 코드를 실행하는 각 thread는 고유한 `tlv_var`를 가지며, 한 thread가 `tlv_var`에 적용한 변경 사항은 다른 thread의 `tlv_var`에 영향을 주지 않습니다.

Mach-O binary에서는 thread local variables와 관련된 data가 특정 section으로 구성됩니다:

- **`__DATA.__thread_vars`**: 이 section에는 thread-local variables의 type 및 initialization status와 같은 metadata가 포함됩니다.
- **`__DATA.__thread_bss`**: 이 section은 명시적으로 초기화되지 않은 thread-local variables에 사용됩니다. zero-initialized data를 위해 따로 할당된 memory 영역의 일부입니다.

Mach-O는 thread가 종료될 때 thread-local variables를 관리하기 위한 **`tlv_atexit`**이라는 전용 API도 제공합니다. 이 API를 사용하면 thread가 종료될 때 thread-local data를 정리하는 특수 function인 **destructor**를 **register**할 수 있습니다.

### Threading Priorities

Thread priorities를 이해하려면 operating system이 어떤 thread를 언제 실행할지 결정하는 방식을 살펴봐야 합니다. 이 결정은 각 thread에 할당된 priority level의 영향을 받습니다. macOS 및 Unix-like system에서는 `nice`, `renice`, Quality of Service (QoS) class와 같은 개념을 사용해 이를 처리합니다.

#### Nice and Renice

1. **Nice:**
- process의 `nice` value는 해당 process의 priority에 영향을 주는 숫자입니다. 모든 process에는 -20(가장 높은 priority)부터 19(가장 낮은 priority)까지의 nice value가 있습니다. process가 생성될 때 기본 nice value는 일반적으로 0입니다.
- 더 낮은 nice value(-20에 가까운 값)는 process를 더 "selfish"하게 만들어, 더 높은 nice value를 가진 다른 process에 비해 더 많은 CPU time을 사용하게 합니다.
2. **Renice:**
- `renice`는 이미 실행 중인 process의 nice value를 변경하는 command입니다. 이를 사용하면 새로운 nice value에 따라 process의 CPU time 할당을 늘리거나 줄여 priority를 동적으로 조정할 수 있습니다.
- 예를 들어 process에 일시적으로 더 많은 CPU resource가 필요한 경우 `renice`를 사용해 nice value를 낮출 수 있습니다.

#### Quality of Service (QoS) Classes

QoS class는 특히 **Grand Central Dispatch (GCD)**를 지원하는 macOS와 같은 system에서 thread priorities를 처리하는 보다 현대적인 방식입니다. QoS class를 사용하면 developer가 작업의 중요도나 긴급성에 따라 작업을 서로 다른 level로 **categorize**할 수 있습니다. macOS는 이러한 QoS class에 따라 thread prioritization을 자동으로 관리합니다:

1. **User Interactive:**
- 현재 user와 상호 작용하거나, 좋은 user experience를 제공하기 위해 즉각적인 결과가 필요한 작업을 위한 class입니다. interface의 responsiveness를 유지하기 위해 이러한 작업에는 가장 높은 priority가 부여됩니다(예: animation 또는 event handling).
2. **User Initiated:**
- document 열기 또는 computation이 필요한 button 클릭처럼 user가 시작하고 즉각적인 결과를 기대하는 작업입니다. 높은 priority지만 user interactive보다는 낮습니다.
3. **Utility:**
- 장시간 실행되며 일반적으로 progress indicator를 표시하는 작업입니다(예: file download, data import). user-initiated 작업보다 priority가 낮으며 즉시 완료될 필요는 없습니다.
4. **Background:**
- user에게 표시되지 않고 background에서 동작하는 작업을 위한 class입니다. indexing, syncing 또는 backup과 같은 작업이 여기에 해당할 수 있습니다. 가장 낮은 priority를 가지며 system performance에 미치는 영향이 최소화됩니다.

QoS class를 사용하면 developer가 정확한 priority number를 직접 관리하지 않고 작업의 특성에 집중할 수 있으며, system이 그에 맞게 CPU resource를 최적화합니다.

또한 scheduler가 고려할 scheduling parameter 집합을 지정하는 서로 다른 **thread scheduling policy**도 있습니다. 이는 `thread_policy_[set/get]`을 사용해 설정할 수 있습니다. race condition attack에서 유용할 수 있습니다.

## macOS Process Abuse

macOS는 **process가 상호 작용하고, 통신하며, data를 공유**할 수 있는 다양한 mechanism을 제공합니다. 이러한 mechanism은 정상적인 system 동작에 필수적이지만, attacker는 이를 injection, code execution 또는 data access에 악용할 수 있습니다.

### Library Injection

Library Injection은 attacker가 **process에 malicious library를 load하도록 강제**하는 technique입니다. injection된 library는 target process의 context에서 실행되므로, attacker는 해당 process와 동일한 permission 및 access 권한을 얻게 됩니다.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking은 software code 내부의 **function call** 또는 message를 **intercept**하는 것을 의미합니다. function을 hooking하면 attacker는 process의 **동작을 변경**하거나, sensitive data를 관찰하거나, execution flow를 제어할 수도 있습니다.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC)은 서로 분리된 process가 **data를 공유하고 교환**하는 여러 method를 의미합니다. IPC는 많은 정상적인 application의 기본 요소이지만, process isolation을 무력화하거나, sensitive information을 leak하거나, unauthorized action을 수행하는 데 악용될 수도 있습니다.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

특정 env variable과 함께 실행되는 Electron application은 process injection에 취약할 수 있습니다:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` 및 `--use-fake-ui-for-media-stream` flag를 사용해 **man in the browser attack**을 수행할 수 있습니다. 이를 통해 keystroke와 traffic, cookie를 훔치고 page에 script를 injection할 수 있습니다:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB file은 application 내부의 **user interface (UI) element**와 그 상호 작용을 **정의**합니다. 그러나 NIB file은 **arbitrary command를 실행**할 수 있으며, **NIB file이 수정**되어도 **Gatekeeper는 이미 실행된 application의 재실행을 차단하지 않습니다**. 따라서 arbitrary program이 arbitrary command를 실행하도록 만드는 데 사용될 수 있습니다:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** 또는 **`JDK_JAVA_OPTIONS`**를 통해 JVM option을 injection하고 application 시작 전에 Java 또는 native agent를 load할 수 있습니다.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

`Main` 실행 전에 **`DOTNET_STARTUP_HOOKS`**를 통해 .NET application에 code를 injection하거나, 필요한 prerequisite이 존재할 때 .NET debugging functionality를 악용할 수 있습니다.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash는 **`BASH_ENV`**를 읽고, zsh는 **`$ZDOTDIR/.zshenv`**를 읽으며, fish는 **`XDG_CONFIG_HOME`** 또는 **`XDG_DATA_DIRS`** 아래의 configuration을 읽습니다. 각각 intended command 실행 전에 제어 가능한 startup file을 실행할 수 있습니다:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** 또는 **`PHP_INI_SCAN_DIR`**은 target script보다 먼저 **`auto_prepend_file`**을 실행하는 제어 가능한 PHP configuration을 load할 수 있습니다.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

standalone Lua interpreter는 target script를 처리하기 전에 **`LUA_INIT`**(또는 version-specific variant)에서 code 또는 `@file`을 실행합니다.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** 및 **`R_PROFILE`**은 R code를 포함하는 startup profile로 redirect합니다. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**와 R library path를 함께 사용하면 설치된 package를 자동으로 load할 수도 있습니다.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**는 `config/startup.jl`이 자동으로 실행되는 depot으로 redirect합니다.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** 또는 **`ERL_ZFLAGS`**는 payload file 없이도 Erlang VM **`-eval`** expression을 injection할 수 있습니다. Elixir workload도 일반적으로 동일한 VM을 시작합니다.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 및 **`OCTAVE_VERSION_INITFILE`**은 Octave startup script로 redirect합니다.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

macOS 및 Linux에서 **`XDG_CONFIG_HOME`**은 `pwsh` 시작 시 실행되는 PowerShell user profile로 redirect할 수 있습니다.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script가 다음 위치에서 arbitrary code를 실행하도록 만드는 다양한 option을 확인할 수 있습니다:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

ruby env variable을 악용해 arbitrary script가 arbitrary code를 실행하도록 만들 수도 있습니다:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** 및 **`BROWSER`** standard-library chain은 warning-filter parsing 중 command를 실행할 수 있습니다. file-backed alternative 방식은 **`PYTHONPATH`**에 `sitecustomize.py`를 배치하여, 일반적인 `site` initialization 과정에서 target script보다 먼저 이를 import하도록 합니다. **`PYTHONSTARTUP`**과 같은 interactive-only variable은 적용 범위가 더 좁습니다.

**`pyinstaller`**로 compile된 executable은 embedded python을 사용해 실행되더라도 이러한 environmental variable을 사용하지 않는다는 점에 유의해야 합니다.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

이와 별도로 Homebrew는 일반적으로 `/opt/homebrew` 아래에 Python을 설치하며, local `admin` group의 member가 launcher를 교체할 수 있습니다. 이는 environment-variable injection이 아니라 writable-binary hijack이므로, exploitable한 것으로 판단하기 전에 ownership과 ACL을 확인해야 합니다.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield)는 process injection을 detect하고 block하는 open-source **EndpointSecurity** 기반 application입니다. 다음 항목을 alert하므로, Endpoint Security를 통해 어떤 signal을 관찰할 수 있는지 확인하는 데 유용한 reference입니다:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- process exec 시 **Injection environment variable**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` 및 `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** call — 한 process가 다른 process의 task port를 요청하는 것으로, 해당 process에 injection하기 위한 prerequisite입니다.
- **Electron debugging argument** — `--inspect`, `--inspect-brk` 및 `--remote-debugging-port`. 이는 Electron app을 debug mode로 시작하고 누구나 attach하여 해당 app에서 code를 실행할 수 있게 합니다.<sup>[[3]](#references)</sup>
- **Privilege level을 넘나드는 symlink/hardlink creation** — 일반 user로 link를 생성한 뒤 privileged location을 가리키게 하는 고전적인 "일반 user로 link를 심고 privileged location을 가리키는" primitive입니다. **symlink는 alert할 수는 있지만 block할 수는 없음**에 유의해야 합니다. EndpointSecurity는 link가 생성되기 전에 link destination을 노출하지 않습니다.

### Calls made by other processes

[**이 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)에서 **`task_name_for_pid`** function을 사용해 다른 **process에 code를 injection하는 process**에 대한 정보를 얻은 다음, 해당 다른 process에 대한 정보를 얻는 방법을 확인할 수 있습니다.<sup>[[4]](#references)</sup>

이 function을 call하려면 해당 process를 실행 중인 user와 **동일한 uid**이거나 **root**여야 합니다(그리고 이 function은 process에 대한 정보를 반환할 뿐, code를 injection하는 방법을 제공하지 않습니다).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron app이 secret을 confidential하게 저장할 수 없는 이유: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modification detection](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
