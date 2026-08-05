# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

프로세스는 실행 중인 실행 파일의 인스턴스입니다. 하지만 프로세스는 코드를 실행하지 않으며, 코드를 실행하는 것은 스레드입니다. 따라서 **프로세스는 실행 중인 스레드를 위한 컨테이너**일 뿐이며 메모리, 디스크립터, 포트, 권한 등을 제공합니다.

전통적으로 프로세스는 PID 1을 제외한 다른 프로세스 내부에서 **`fork`**를 호출하여 시작되었습니다. **`fork`**는 현재 프로세스의 정확한 복사본을 생성하며, 이후 **자식 프로세스**는 일반적으로 **`execve`**를 호출하여 새로운 실행 파일을 로드하고 실행합니다. 그다음 메모리 복사 없이 이 프로세스를 더 빠르게 만들기 위해 **`vfork`**가 도입되었습니다.\
이후 **`posix_spawn`**이 도입되어 **`vfork`**와 **`execve`**를 한 번의 호출로 결합하고 다음 플래그를 사용할 수 있게 되었습니다:

- `POSIX_SPAWN_RESETIDS`: 유효 ID를 실제 ID로 재설정
- `POSIX_SPAWN_SETPGROUP`: 프로세스 그룹 소속 설정
- `POSUX_SPAWN_SETSIGDEF`: signal 기본 동작 설정
- `POSIX_SPAWN_SETSIGMASK`: signal mask 설정
- `POSIX_SPAWN_SETEXEC`: 동일한 프로세스에서 Exec 수행 (`execve`와 유사하지만 더 많은 옵션 제공)
- `POSIX_SPAWN_START_SUSPENDED`: 일시 중단된 상태로 시작
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR 없이 시작
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc의 Nano allocator 사용
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 데이터 세그먼트에서 `rwx` 허용
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 기본적으로 exec(2) 시 모든 file description 닫기
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide의 상위 비트를 무작위화

또한 `posix_spawn`을 사용하면 생성되는 프로세스의 일부 측면을 제어하는 **`posix_spawnattr`** 배열과 디스크립터의 상태를 수정하는 **`posix_spawn_file_actions`**를 지정할 수 있습니다.

프로세스가 종료되면 signal `SIGCHLD`와 함께 **반환 코드를 부모 프로세스에 전달**합니다(부모 프로세스가 종료된 경우 새 부모는 PID 1입니다). 부모는 `wait4()` 또는 `waitid()`를 호출하여 이 값을 가져와야 하며, 그때까지 자식 프로세스는 여전히 목록에 표시되지만 리소스를 소비하지 않는 zombie 상태로 남아 있습니다.

### PIDs

PIDs(process identifiers)는 고유한 프로세스를 식별합니다. XNU에서 **PIDs**는 **64비트**이며 단조롭게 증가하고 **절대 wrap되지 않습니다**(abuse 방지 목적).

### Process Groups, Sessions & Coalations

**프로세스**는 관리를 쉽게 하기 위해 **그룹**에 삽입될 수 있습니다. 예를 들어 shell script의 명령은 동일한 프로세스 그룹에 속하므로 kill 등을 사용하여 **함께 signal을 보낼** 수 있습니다.\
프로세스를 **session으로 그룹화**하는 것도 가능합니다. 프로세스가 session(`setsid(2)`)을 시작하면, 자식 프로세스는 자체 session을 시작하지 않는 한 해당 session 내부에 배치됩니다.

Coalition은 Darwin에서 프로세스를 그룹화하는 또 다른 방법입니다. 프로세스가 coalition에 참여하면 pool 리소스에 액세스하고, ledger를 공유하거나 Jetsam의 대상이 될 수 있습니다. Coalition에는 Leader, XPC service, Extension 등 서로 다른 역할이 있습니다.

### Credentials & Personae

각 프로세스는 시스템에서 **자신의 권한을 식별하는** **credentials**를 보유합니다. 각 프로세스에는 기본 `uid` 하나와 기본 `gid` 하나가 있으며(여러 그룹에 속할 수는 있음),\
binary에 `setuid/setgid` bit가 있으면 사용자 및 그룹 ID를 변경할 수도 있습니다.\
새로운 uids/gids를 **설정**하는 여러 함수가 있습니다.

syscall **`persona`**는 **credentials**의 **대체** 집합을 제공합니다. Persona를 채택하면 해당 uid, gid 및 그룹 멤버십을 **동시에** 사용하게 됩니다. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)에서 struct를 확인할 수 있습니다:
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

1. **POSIX Threads (pthreads):** macOS는 표준 C/C++ threading API의 일부인 POSIX threads(`pthreads`)를 지원합니다. macOS의 pthreads 구현은 공개적으로 제공되는 `libpthread` 프로젝트에서 비롯된 `/usr/lib/system/libsystem_pthread.dylib`에 있습니다. 이 library는 threads를 생성하고 관리하는 데 필요한 functions를 제공합니다.
2. **Threads 생성:** `pthread_create()` function은 새로운 threads를 생성하는 데 사용됩니다. 내부적으로 이 function은 XNU kernel(macOS가 기반으로 하는 kernel)에 특화된 lower-level system call인 `bsdthread_create()`를 호출합니다. 이 system call은 thread 동작을 지정하는 `pthread_attr` (attributes)에서 파생된 다양한 flags를 전달받으며, 여기에는 scheduling policies와 stack size가 포함됩니다.
- **기본 Stack Size:** 새로운 threads의 기본 stack size는 512 KB입니다. 일반적인 작업에는 충분하지만, 더 많거나 적은 공간이 필요한 경우 thread attributes를 통해 조정할 수 있습니다.
3. **Thread 초기화:** `__pthread_init()` function은 thread 설정 과정에서 매우 중요하며, stack의 위치와 크기 등의 세부 정보가 포함될 수 있는 environment variables를 `env[]` argument를 사용해 parse합니다.

#### macOS에서 Thread 종료

1. **Threads 종료:** Threads는 일반적으로 `pthread_exit()`를 호출하여 종료합니다. 이 function을 사용하면 thread가 필요한 cleanup을 수행하고 정상적으로 종료되며, joiners에 return value를 전달할 수 있습니다.
2. **Thread Cleanup:** `pthread_exit()`를 호출하면 `pthread_terminate()` function이 호출되어 연결된 모든 thread structures를 제거합니다. 이 function은 Mach thread ports(Mach는 XNU kernel의 communication subsystem)를 deallocate하고, thread와 연결된 kernel-level structures를 제거하는 syscall인 `bsdthread_terminate`를 호출합니다.

#### Synchronization Mechanisms

macOS는 shared resources에 대한 access를 관리하고 race conditions를 방지하기 위해 여러 synchronization primitives를 제공합니다. 이는 data integrity와 system stability를 보장하는 데 중요한 multi-threading 환경에서 사용됩니다:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** 60 bytes의 memory footprint를 가진 standard mutex입니다(56 bytes는 mutex, 4 bytes는 signature).
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex와 유사하지만 더 빠른 operations에 최적화되어 있으며, 크기도 60 bytes입니다.
2. **Condition Variables:**
- 특정 conditions가 발생할 때까지 대기하는 데 사용되며, 크기는 44 bytes입니다(40 bytes와 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables의 configuration attributes이며, 크기는 12 bytes입니다.
3. **Once Variable (Signature: 0x4f4e4345):**
- initialization code가 한 번만 실행되도록 보장합니다. 크기는 12 bytes입니다.
4. **Read-Write Locks:**
- 여러 readers 또는 한 번에 하나의 writer를 허용하여 shared data에 효율적으로 access할 수 있도록 합니다.
- **Read Write Lock (Signature: 0x52574c4b):** 크기는 196 bytes입니다.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks의 attributes이며, 크기는 20 bytes입니다.

> [!TIP]
> 이러한 objects의 마지막 4 bytes는 overflow를 감지하는 데 사용됩니다.

### Thread Local Variables (TLV)

Mach-O files(macOS의 executables 형식)의 맥락에서 **Thread Local Variables (TLV)**는 multi-threaded application에서 **각 thread**에 특화된 variables를 선언하는 데 사용됩니다. 이를 통해 각 thread가 variable의 별도 instance를 가지게 하며, mutexes와 같은 명시적인 synchronization mechanisms 없이도 conflicts를 방지하고 data integrity를 유지할 수 있습니다.

C 및 관련 languages에서는 **`__thread`** keyword를 사용하여 thread-local variable을 선언할 수 있습니다. 다음은 예제에서 해당 keyword가 작동하는 방식입니다:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
이 snippet은 `tlv_var`를 thread-local variable로 정의합니다. 이 코드를 실행하는 각 thread는 고유한 `tlv_var`를 가지며, 한 thread가 `tlv_var`에 적용한 변경 사항은 다른 thread의 `tlv_var`에 영향을 주지 않습니다.

Mach-O binary에서 thread local variables와 관련된 data는 특정 section으로 구성됩니다:

- **`__DATA.__thread_vars`**: 이 section에는 thread-local variables의 type과 initialization status 같은 metadata가 포함됩니다.
- **`__DATA.__thread_bss`**: 이 section은 명시적으로 초기화되지 않은 thread-local variables에 사용됩니다. zero-initialized data를 위해 따로 할당된 memory 영역의 일부입니다.

Mach-O는 thread가 종료될 때 thread-local variables를 관리하기 위한 **`tlv_atexit`**라는 특정 API도 제공합니다. 이 API를 사용하면 thread가 종료될 때 thread-local data를 정리하는 특수 function인 **destructor**를 **register**할 수 있습니다.

### Threading Priorities

Thread priority를 이해하려면 operating system이 어떤 thread를 언제 실행할지 결정하는 방식을 살펴봐야 합니다. 이 결정은 각 thread에 할당된 priority level의 영향을 받습니다. macOS 및 Unix-like systems에서는 `nice`, `renice`, Quality of Service (QoS) classes와 같은 개념을 사용해 이를 처리합니다.

#### Nice and Renice

1. **Nice:**
- process의 `nice` value는 해당 process의 priority에 영향을 주는 숫자입니다. 모든 process는 -20 (가장 높은 priority)부터 19 (가장 낮은 priority)까지의 nice value를 가집니다. process가 생성될 때의 기본 nice value는 일반적으로 0입니다.
- 더 낮은 nice value(-20에 가까운 값)는 process를 더 "이기적으로" 만들어, 더 높은 nice value를 가진 다른 process보다 더 많은 CPU time을 사용하게 합니다.
2. **Renice:**
- `renice`는 이미 실행 중인 process의 nice value를 변경하는 command입니다. 이를 사용하면 새로운 nice value에 따라 process의 CPU time 할당을 늘리거나 줄이는 등 process priority를 동적으로 조정할 수 있습니다.
- 예를 들어 process에 일시적으로 더 많은 CPU resource가 필요하다면 `renice`를 사용해 nice value를 낮출 수 있습니다.

#### Quality of Service (QoS) Classes

QoS classes는 특히 **Grand Central Dispatch (GCD)**를 지원하는 macOS와 같은 systems에서 thread priority를 처리하는 보다 현대적인 방식입니다. QoS classes를 사용하면 developer가 work를 중요도 또는 긴급도에 따라 서로 다른 level로 **categorize**할 수 있습니다. macOS는 이러한 QoS classes를 기반으로 thread prioritization을 자동으로 관리합니다:

1. **User Interactive:**
- 이 class는 현재 user와 상호작용 중이거나 좋은 user experience를 위해 즉각적인 결과가 필요한 task를 위한 것입니다. interface의 responsiveness를 유지하기 위해 이러한 task에는 가장 높은 priority가 부여됩니다 (예: animation 또는 event handling).
2. **User Initiated:**
- document 열기나 computation이 필요한 button 클릭처럼 user가 시작했으며 즉각적인 결과를 기대하는 task입니다. 높은 priority이지만 user interactive보다는 낮습니다.
3. **Utility:**
- 장시간 실행되며 일반적으로 progress indicator를 표시하는 task입니다 (예: file download, data import). user-initiated task보다 priority가 낮으며 즉시 완료될 필요는 없습니다.
4. **Background:**
- user에게 보이지 않는 상태로 background에서 동작하는 task를 위한 class입니다. indexing, syncing 또는 backup 같은 task가 해당될 수 있습니다. 가장 낮은 priority를 가지며 system performance에 미치는 영향이 최소화됩니다.

QoS classes를 사용하면 developer는 정확한 priority number를 관리할 필요 없이 task의 성격에 집중할 수 있으며, system이 그에 따라 CPU resource를 최적화합니다.

또한 scheduler가 고려할 scheduling parameter set을 지정하는 서로 다른 **thread scheduling policies**가 있습니다. 이는 `thread_policy_[set/get]`을 사용해 수행할 수 있습니다. 이는 race condition attack에 유용할 수 있습니다.

## MacOS Process Abuse

다른 operating system과 마찬가지로 MacOS는 **process가 상호작용하고, 통신하며, data를 공유**할 수 있는 다양한 method와 mechanism을 제공합니다. 이러한 technique은 효율적인 system 동작에 필수적이지만, threat actor가 이를 악용해 **malicious activity를 수행**할 수도 있습니다.

### Library Injection

Library Injection은 attacker가 **malicious library를 load하도록 process를 강제하는** technique입니다. injection이 완료되면 해당 library는 target process의 context에서 실행되므로 attacker에게 process와 동일한 permission 및 access가 제공됩니다.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking은 software code 내에서 **function call** 또는 message를 **intercept**하는 작업입니다. function을 hooking하면 attacker는 process의 **동작을 수정**하거나, sensitive data를 관찰하거나, execution flow를 제어할 수도 있습니다.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC)은 서로 분리된 process가 **data를 공유하고 교환**하는 다양한 method를 의미합니다. IPC는 많은 legitimate application의 기반이지만, process isolation을 무력화하거나, sensitive information을 leak하거나, unauthorized action을 수행하는 데 악용될 수도 있습니다.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

특정 env variable과 함께 실행되는 Electron application은 process injection에 취약할 수 있습니다:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` 및 `--use-fake-ui-for-media-stream` flag를 사용해 **man in the browser attack**을 수행할 수 있습니다. 이를 통해 keystroke와 traffic, cookie를 훔치고 page에 script를 injection할 수 있습니다...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB file은 application 내 **user interface (UI) element**와 해당 element의 상호작용을 **정의**합니다. 그러나 NIB file은 **arbitrary command를 실행**할 수 있으며, 이미 실행된 application의 **NIB file이 수정**되어도 **Gatekeeper는 해당 application의 재실행을 차단하지 않습니다**. 따라서 이를 사용해 arbitrary program이 arbitrary command를 실행하도록 만들 수 있습니다:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

일부 java capability (예: **`_JAVA_OPTS`** env variable)를 악용해 java application이 **arbitrary code/command**를 실행하도록 만들 수 있습니다.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

**.Net debugging functionality** (runtime hardening과 같은 macOS protection으로 보호되지 않음)를 **악용**해 .Net application에 code를 injection할 수 있습니다.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Perl script가 arbitrary code를 실행하도록 만드는 다양한 option은 다음을 참고하세요:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

ruby env variable을 악용해 arbitrary script가 arbitrary code를 실행하도록 만드는 것도 가능합니다:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

environment variable **`PYTHONINSPECT`**가 set되어 있으면 python process는 종료된 후 python cli로 진입합니다. 또한 **`PYTHONSTARTUP`**을 사용해 interactive session 시작 시 실행할 python script를 지정할 수도 있습니다.\
단, **`PYTHONINSPECT`**가 interactive session을 생성할 때는 **`PYTHONSTARTUP`** script가 실행되지 않는다는 점에 유의하세요.

**`PYTHONPATH`** 및 **`PYTHONHOME`**과 같은 다른 env variable도 python command가 arbitrary code를 실행하도록 만드는 데 유용할 수 있습니다.

**`pyinstaller`**로 compile된 executable은 embedded python을 사용해 실행 중이더라도 이러한 environmental variable을 사용하지 않는다는 점에 유의하세요.

> [!CAUTION]
> 전반적으로 environment variable을 악용해 python이 arbitrary code를 실행하도록 만드는 방법은 찾지 못했습니다.\
> 그러나 대부분의 사용자는 **Hombrew**를 사용해 pyhton을 install하며, 이 경우 default admin user가 **writable location**에 pyhton을 install하게 됩니다. 다음과 같은 방식으로 이를 hijack할 수 있습니다:
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
> python을 실행할 때는 **root**조차도 이 code를 실행하게 됩니다.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield)는 process injection을 detect하고 block하는 open source **EndpointSecurity** 기반 application입니다. 다음 event에 alert를 생성하므로 ES에서 실제로 관찰 가능한 signal이 무엇인지 확인하기 위한 좋은 reference입니다:<sup>[[1]](#references)</sup>

- process exec 시 **Injection environment variable**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` 및 `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** call — 한 process가 다른 process의 task port를 요청하는 것으로, 해당 process에 injection하기 위한 prerequisite입니다.
- **Electron debugging argument** — `--inspect`, `--inspect-brk` 및 `--remote-debugging-port`. 이 argument는 Electron app을 debug mode로 시작하고 누구나 attach하여 해당 app에서 code를 실행할 수 있도록 합니다.
- **privilege level 간 symlink/hardlink 생성** — 일반 user로 link를 생성한 뒤 privileged location을 가리키도록 하는 고전적인 "plant a link as a normal user, point it at a privileged location" primitive입니다. 단, **symlink는 alert할 수는 있지만 block할 수는 없습니다**: EndpointSecurity는 link 생성 전에 link destination을 노출하지 않습니다.

### Calls made by other processes

[**이 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)에서 **process에 code를 injection하는 다른 process**에 대한 정보를 얻은 다음 해당 process에 대한 정보를 확인하기 위해 **`task_name_for_pid`** function을 사용하는 방법을 확인할 수 있습니다.<sup>[[4]](#references)</sup>

이 function을 호출하려면 해당 process를 실행 중인 user와 **동일한 uid**이거나 **root**여야 합니다 (이 function은 process에 대한 정보를 반환할 뿐, code를 injection하는 방법은 제공하지 않습니다).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
