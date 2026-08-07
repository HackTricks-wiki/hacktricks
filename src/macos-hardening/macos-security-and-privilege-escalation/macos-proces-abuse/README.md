# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

프로세스는 실행 중인 executable의 인스턴스이지만, 프로세스가 code를 실행하는 것은 아니며 thread가 실행합니다. 따라서 **프로세스는 실행 중인 thread를 위한 container**일 뿐이며, memory, descriptor, port, permission 등을 제공합니다.

전통적으로 프로세스는 **`fork`**를 호출하여 다른 프로세스(PID 1 제외) 내부에서 시작되었습니다. `fork`는 현재 프로세스의 정확한 복사본을 생성하며, 이후 **child process**는 일반적으로 **`execve`**를 호출하여 새로운 executable을 load하고 실행합니다. 이후 memory copying 없이 이 프로세스를 더 빠르게 수행하기 위해 **`vfork`**가 도입되었습니다.\
그 다음 **`posix_spawn`**이 도입되어 한 번의 호출로 **`vfork`**와 **`execve`**를 결합하고 다음 flags를 지원했습니다:

- `POSIX_SPAWN_RESETIDS`: effective id를 real id로 재설정
- `POSIX_SPAWN_SETPGROUP`: process group 소속 설정
- `POSUX_SPAWN_SETSIGDEF`: signal 기본 동작 설정
- `POSIX_SPAWN_SETSIGMASK`: signal mask 설정
- `POSIX_SPAWN_SETEXEC`: 동일한 프로세스에서 exec 수행(`execve`와 유사하지만 더 많은 options 제공)
- `POSIX_SPAWN_START_SUSPENDED`: suspended 상태로 시작
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR 없이 시작
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc의 Nano allocator 사용
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segment에서 `rwx` 허용
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 기본적으로 exec(2) 시 모든 file description을 close
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide의 high bits를 randomize

또한 `posix_spawn`은 생성되는 프로세스의 일부 측면을 제어하는 **`posix_spawnattr`** 배열과 descriptor의 상태를 수정하는 **`posix_spawn_file_actions`**를 지정할 수 있습니다.

프로세스가 종료되면 signal `SIGCHLD`를 사용하여 **return code를 parent process에 전달**합니다(parent가 종료된 경우 새로운 parent는 PID 1입니다). Parent는 `wait4()` 또는 `waitid()`를 호출하여 이 값을 가져와야 하며, 그때까지 child는 여전히 목록에 표시되지만 resource를 사용하지 않는 zombie 상태로 유지됩니다.

### PIDs

PID(process identifier)는 고유한 프로세스를 식별합니다. XNU에서 **PID**는 **64bits**이며 단조롭게 증가하고 **절대 wrap되지 않습니다**(abuse 방지 목적).

### Process Groups, Sessions & Coalations

**프로세스**는 처리를 쉽게 하기 위해 **group**에 삽입될 수 있습니다. 예를 들어 shell script의 command는 동일한 process group에 속하므로 kill 등을 사용하여 **함께 signal을 보낼** 수 있습니다.\
프로세스를 **session으로 group화**하는 것도 가능합니다. 프로세스가 session(`setsid(2)`)을 시작하면, child process는 자체 session을 시작하지 않는 한 해당 session 내부에 배치됩니다.

Coalition은 Darwin에서 프로세스를 group화하는 또 다른 방식입니다. 프로세스가 coalition에 참여하면 pool resource에 접근하고, ledger를 공유하거나 Jetsam의 대상이 될 수 있습니다. Coalition에는 Leader, XPC service, Extension이라는 서로 다른 role이 있습니다.

### Credentials & Personae

각 프로세스는 system에서 해당 **privilege를 식별하는** **credential**을 보유합니다. 각 프로세스에는 하나의 primary `uid`와 하나의 primary `gid`가 있으며(여러 group에 속할 수는 있음),\
binary에 `setuid/setgid` bit가 설정되어 있다면 user 및 group id를 변경할 수도 있습니다.\
새로운 uid/gid를 **설정하는** 여러 function이 존재합니다.

**`persona`** syscall은 **credential**의 **alternate** set을 제공합니다. Persona를 채택하면 해당 uid, gid 및 group membership을 **동시에** 적용합니다. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)에서 다음 struct를 확인할 수 있습니다:
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

1. **POSIX Threads (pthreads):** macOS는 C/C++용 표준 threading API의 일부인 POSIX threads(`pthreads`)를 지원합니다. macOS의 pthreads 구현은 공개적으로 제공되는 `libpthread` 프로젝트에서 제공되는 `/usr/lib/system/libsystem_pthread.dylib`에 있습니다. 이 library는 thread를 생성하고 관리하는 데 필요한 함수를 제공합니다.
2. **Thread 생성:** `pthread_create()` 함수는 새로운 thread를 생성하는 데 사용됩니다. 내부적으로 이 함수는 XNU kernel(macOS의 기반이 되는 kernel)에 특화된 하위 수준 system call인 `bsdthread_create()`를 호출합니다. 이 system call은 scheduling policy와 stack size를 비롯해 thread 동작을 지정하는 `pthread_attr`(attributes)에서 파생된 여러 flag를 전달받습니다.
- **기본 Stack Size:** 새로운 thread의 기본 stack size는 512 KB입니다. 일반적인 작업에는 충분하지만, 더 많거나 적은 공간이 필요한 경우 thread attributes를 통해 조정할 수 있습니다.
3. **Thread 초기화:** `__pthread_init()` 함수는 thread 설정 중 중요한 역할을 하며, stack의 위치와 크기 정보가 포함될 수 있는 environment variable을 `env[]` 인자를 사용해 parsing합니다.

#### macOS에서의 Thread 종료

1. **Thread 종료:** Thread는 일반적으로 `pthread_exit()`를 호출하여 종료합니다. 이 함수는 thread가 정리 작업을 수행하고 정상적으로 종료되도록 하며, joiner에게 return value를 전달할 수 있게 합니다.
2. **Thread 정리:** `pthread_exit()`를 호출하면 `pthread_terminate()` 함수가 호출되며, 이 함수는 연결된 모든 thread structure를 제거합니다. Mach thread port(Mach는 XNU kernel의 communication subsystem)를 deallocate하고, thread와 연결된 kernel-level structure를 제거하는 syscall인 `bsdthread_terminate`를 호출합니다.

#### Synchronization Mechanism

Shared resource에 대한 access를 관리하고 race condition을 방지하기 위해 macOS는 여러 synchronization primitive를 제공합니다. 이는 data integrity와 system stability를 보장하는 데 중요한 multi-threading 환경에서 사용됩니다.

1. **Mutex:**
- **Regular Mutex (Signature: 0x4D555458):** 60 bytes의 memory footprint를 사용하는 standard mutex입니다(56 bytes는 mutex, 4 bytes는 signature).
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex와 유사하지만 더 빠른 operation을 위해 최적화되어 있으며, 크기도 60 bytes입니다.
2. **Condition Variable:**
- 특정 condition이 발생할 때까지 대기하는 데 사용되며, 크기는 44 bytes입니다(40 bytes와 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variable의 configuration attributes이며, 크기는 12 bytes입니다.
3. **Once Variable (Signature: 0x4f4e4345):**
- 초기화 code가 한 번만 실행되도록 보장합니다. 크기는 12 bytes입니다.
4. **Read-Write Lock:**
- 여러 reader 또는 한 번에 하나의 writer가 access할 수 있도록 하여 shared data에 효율적으로 access할 수 있게 합니다.
- **Read Write Lock (Signature: 0x52574c4b):** 크기는 196 bytes입니다.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock의 attributes이며, 크기는 20 bytes입니다.

> [!TIP]
> 이러한 object의 마지막 4 bytes는 overflow를 감지하는 데 사용됩니다.

### Thread Local Variables (TLV)

Mach-O file(macOS의 executable format)의 context에서 **Thread Local Variables (TLV)**는 multi-threaded application에서 **각 thread**에 고유한 variable을 선언하는 데 사용됩니다. 이를 통해 각 thread가 variable의 별도 instance를 가지게 하며, mutex와 같은 명시적인 synchronization mechanism 없이도 conflict를 방지하고 data integrity를 유지할 수 있습니다.

C 및 관련 language에서는 **`__thread`** keyword를 사용하여 thread-local variable을 선언할 수 있습니다. 다음은 예제에서 이 keyword가 동작하는 방식입니다:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
이 snippet은 `tlv_var`를 thread-local variable로 정의합니다. 이 코드를 실행하는 각 thread는 고유한 `tlv_var`를 가지며, 한 thread가 `tlv_var`에 적용한 변경 사항은 다른 thread의 `tlv_var`에 영향을 주지 않습니다.

Mach-O binary에서는 thread local variables와 관련된 data가 특정 sections에 구성됩니다:

- **`__DATA.__thread_vars`**: 이 section에는 thread-local variables의 type 및 initialization status와 같은 metadata가 포함됩니다.
- **`__DATA.__thread_bss`**: 이 section은 명시적으로 초기화되지 않은 thread-local variables에 사용됩니다. zero-initialized data를 위해 따로 할당된 memory 영역의 일부입니다.

Mach-O는 thread가 종료될 때 thread-local variables를 관리하기 위한 특정 API인 **`tlv_atexit`**도 제공합니다. 이 API를 사용하면 thread가 종료될 때 thread-local data를 정리하는 특수 function인 **destructors**를 **register**할 수 있습니다.

### Threading Priorities

Thread priorities를 이해하려면 operating system이 어떤 thread를 언제 실행할지 결정하는 방식을 살펴봐야 합니다. 이 결정은 각 thread에 할당된 priority level의 영향을 받습니다. macOS 및 Unix-like systems에서는 `nice`, `renice`, Quality of Service (QoS) classes와 같은 concepts를 사용하여 이를 처리합니다.

#### Nice and Renice

1. **Nice:**
- process의 `nice` value는 해당 process의 priority에 영향을 주는 숫자입니다. 모든 process는 -20 (가장 높은 priority)부터 19 (가장 낮은 priority)까지의 nice value를 가집니다. process가 생성될 때의 default nice value는 일반적으로 0입니다.
- 더 낮은 nice value (-20에 가까운 값)는 process를 더욱 "selfish"하게 만들어, 더 높은 nice value를 가진 다른 process보다 더 많은 CPU time을 사용하도록 합니다.
2. **Renice:**
- `renice`는 이미 실행 중인 process의 nice value를 변경하는 데 사용되는 command입니다. 새로운 nice value에 따라 CPU time 할당을 늘리거나 줄이는 등 process의 priority를 동적으로 조정할 수 있습니다.
- 예를 들어 process에 일시적으로 더 많은 CPU resources가 필요한 경우 `renice`를 사용하여 nice value를 낮출 수 있습니다.

#### Quality of Service (QoS) Classes

QoS classes는 특히 **Grand Central Dispatch (GCD)**를 지원하는 macOS와 같은 systems에서 thread priorities를 처리하는 보다 modern한 방식입니다. QoS classes를 사용하면 developers가 작업의 중요도나 긴급성에 따라 작업을 서로 다른 level로 **categorize**할 수 있습니다. macOS는 이러한 QoS classes를 기반으로 thread prioritization을 자동으로 관리합니다:

1. **User Interactive:**
- 현재 user와 상호 작용하거나 좋은 user experience를 위해 즉각적인 결과가 필요한 작업을 위한 class입니다. 이러한 작업에는 interface의 responsiveness를 유지하기 위해 가장 높은 priority가 부여됩니다 (예: animations 또는 event handling).
2. **User Initiated:**
- document 열기 또는 computation이 필요한 button 클릭처럼 user가 시작하고 즉각적인 결과를 기대하는 작업입니다. 높은 priority이지만 user interactive보다는 낮습니다.
3. **Utility:**
- 장시간 실행되며 일반적으로 progress indicator를 표시하는 작업입니다 (예: file 다운로드 또는 data import). user-initiated 작업보다 priority가 낮고 즉시 완료될 필요는 없습니다.
4. **Background:**
- user에게 보이지 않는 상태로 background에서 동작하는 작업을 위한 class입니다. indexing, syncing 또는 backups와 같은 작업이 해당될 수 있습니다. priority가 가장 낮으며 system performance에 미치는 영향도 최소화됩니다.

QoS classes를 사용하면 developers는 정확한 priority numbers를 직접 관리하지 않고 작업의 특성에 집중할 수 있으며, system이 그에 따라 CPU resources를 최적화합니다.

또한 scheduler가 고려할 scheduling parameters set을 지정하는 데 사용할 수 있는 서로 다른 **thread scheduling policies**가 있습니다. 이는 `thread_policy_[set/get]`를 사용하여 수행할 수 있습니다. race condition attacks에 유용할 수 있습니다.

## MacOS Process Abuse

다른 operating system과 마찬가지로 MacOS는 **process가 상호 작용하고, 통신하며, data를 공유**할 수 있는 다양한 methods와 mechanisms를 제공합니다. 이러한 techniques는 efficient system functioning에 필수적이지만, threat actors가 이를 악용하여 **malicious activities를 수행**할 수도 있습니다.

### Library Injection

Library Injection은 attacker가 **malicious library를 process에 load하도록 강제**하는 technique입니다. injection된 library는 target process의 context에서 실행되므로 attacker에게 해당 process와 동일한 permissions 및 access를 제공합니다.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking은 software code 내의 **function calls** 또는 messages를 **intercept**하는 과정입니다. functions를 hooking하면 attacker는 process의 **behavior를 수정**하고, sensitive data를 관찰하거나, execution flow를 제어할 수도 있습니다.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC)은 서로 분리된 process가 **data를 공유하고 교환**하는 다양한 methods를 의미합니다. IPC는 많은 legitimate applications에 기본적인 기능이지만, process isolation을 무력화하거나, sensitive information을 leak하거나, unauthorized actions를 수행하는 데 악용될 수도 있습니다.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

특정 env variables와 함께 실행되는 Electron applications는 process injection에 취약할 수 있습니다:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` 및 `--use-fake-ui-for-media-stream` flags를 사용하여 **man in the browser attack**을 수행할 수 있습니다. 이를 통해 keystrokes와 traffic, cookies를 훔치고 pages에 scripts를 inject할 수 있습니다:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files는 application 내의 **user interface (UI) elements**와 해당 elements의 interactions를 **정의**합니다. 그러나 NIB files는 **arbitrary commands를 실행**할 수 있으며, **NIB file이 수정**되더라도 **Gatekeeper는 이미 실행된 application이 다시 실행되는 것을 차단하지 않습니다**. 따라서 arbitrary programs가 arbitrary commands를 실행하도록 만드는 데 사용할 수 있습니다:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

특정 java capabilities (예: **`_JAVA_OPTS`** env variable)를 악용하여 java application이 **arbitrary code/commands를 실행**하도록 만들 수 있습니다.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

**.Net debugging functionality를 악용**하여 .Net applications에 code를 inject할 수 있습니다 (runtime hardening과 같은 macOS protections로 보호되지 않음).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Perl script가 arbitrary code를 실행하도록 만드는 다양한 options는 다음에서 확인할 수 있습니다:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

ruby env variables를 악용하여 arbitrary scripts가 arbitrary code를 실행하도록 만드는 것도 가능합니다:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

environment variable **`PYTHONINSPECT`**가 설정되어 있으면 python process는 종료된 후 python cli로 진입합니다. 또한 **`PYTHONSTARTUP`**을 사용하여 interactive session 시작 시 실행할 python script를 지정할 수 있습니다.\
그러나 **`PYTHONINSPECT`**가 interactive session을 생성할 때는 **`PYTHONSTARTUP`** script가 실행되지 않는다는 점에 유의해야 합니다.

**`PYTHONPATH`** 및 **`PYTHONHOME`**과 같은 다른 env variables도 python command가 arbitrary code를 실행하도록 만드는 데 유용할 수 있습니다.

**`pyinstaller`**로 compiled된 executables는 embedded python을 사용하여 실행되더라도 이러한 environmental variables를 사용하지 않는다는 점에 유의해야 합니다.

> [!CAUTION]
> 전반적으로 environment variables를 악용하여 python이 arbitrary code를 실행하도록 만드는 방법은 찾지 못했습니다.\
> 그러나 대부분의 사람들은 **Hombrew**를 사용하여 pyhton을 설치하며, 이 경우 default admin user가 **writable location**에 pyhton이 설치됩니다. 다음과 같은 방식으로 이를 hijack할 수 있습니다:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> **root**도 python을 실행하면 이 code를 실행하게 됩니다.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield)는 process injection을 detect하고 block하는 open source **EndpointSecurity** 기반 application입니다. 다음과 같은 event에 대해 alert를 발생시키므로, ES에서 실제로 관찰 가능한 signals를 확인하는 데 유용한 reference입니다:<sup>[[1]](#references)[[2]](#references)</sup>

- process exec 시 **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` 및 `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — 한 process가 다른 process의 task port를 요청하는 것으로, 해당 process에 injection하기 위한 prerequisite입니다.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` 및 `--remote-debugging-port`. 이러한 arguments는 Electron app을 debug mode로 시작하며 누구나 attach하여 code를 실행할 수 있도록 합니다.<sup>[[3]](#references)</sup>
- **Privilege levels 간 symlink/hardlink creation** — 일반 user로 link를 생성한 뒤 privileged location을 가리키도록 하는 고전적인 "plant a link as a normal user, point it at a privileged location" primitive입니다. 단, **symlinks는 alert할 수는 있지만 block할 수는 없습니다**: EndpointSecurity는 link가 생성되기 전에 link destination을 노출하지 않습니다.

### Calls made by other processes

[**이 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)에서 **`task_name_for_pid`** function을 사용하여 **process에 code를 inject하는 다른 processes**에 대한 information을 얻은 다음, 해당 other process에 대한 information을 얻는 방법을 확인할 수 있습니다.<sup>[[4]](#references)</sup>

해당 function을 call하려면 process를 실행 중인 user와 **동일한 uid**이거나 **root**여야 합니다 (그리고 이 function은 process에 대한 info를 반환할 뿐, code를 inject하는 방법을 제공하지 않습니다).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
