# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` は、`execve()` をまたいだプロセスの privilege 増加を防ぐ kernel hardening 機能です。実際には、この flag が設定されると、setuid binary、setgid binary、または Linux file capabilities を持つファイルを実行しても、プロセスがすでに持っている以上の privilege は付与されません。containerized environments では、多くの privilege-escalation chain が、起動時に privilege を変更する executable を image 内から探すことに依存しているため、これは重要です。

defensive な観点では、`no_new_privs` は namespaces、seccomp、または capability dropping の代替ではありません。これは補強レイヤーです。code execution をすでに取得した後に行われる、特定の follow-up escalation class をブロックします。そのため、helper binary、package-manager artifact、または legacy tool が image に含まれており、partial compromise と組み合わさると危険になる environments で特に有用です。

## Operation

この動作の基盤となる kernel flag は `PR_SET_NO_NEW_PRIVS` です。プロセスに一度設定すると、その後の `execve()` call で privilege を増加させることはできません。重要なのは、プロセスは引き続き binary を実行できるという点です。ただし、その binary を使って、kernel が通常なら許可する privilege boundary を越えることはできません。

kernel の動作は **継承され、不可逆** でもあります。task が一度 `no_new_privs` を設定すると、その bit は `fork()`、`clone()`、`execve()` をまたいで継承され、後から unset することはできません。これは assessments で有用です。container process に `NoNewPrivs: 1` が設定されていれば、完全に別の process tree を見ているのでない限り、descendant も通常はその mode を維持することを意味します。

Kubernetes-oriented environments では、`allowPrivilegeEscalation: false` が container process に対するこの動作に対応します。Docker および Podman style runtime では、通常、security option を通じて明示的に有効化します。OCI layer では、同じ概念が `process.noNewPrivileges` として現れます。

## Important Nuances

`no_new_privs` は **exec-time** の privilege gain をブロックしますが、すべての privilege change をブロックするわけではありません。特に、以下の点に注意してください。

- setuid および setgid transition は `execve()` をまたいで動作しなくなる
- file capabilities は `execve()` 時に permitted set へ追加されない
- AppArmor や SELinux などの LSM は `execve()` 後に constraint を緩和しない
- すでに保持している privilege は、依然として保持している privilege である

最後の点は、運用上重要です。プロセスがすでに root として実行されている場合、すでに危険な capability を持っている場合、または強力な runtime API や writable host mount にすでにアクセスできる場合、`no_new_privs` を設定しても、それらの exposure が無効になるわけではありません。これは privilege-escalation chain における一般的な **next step** を 1 つ取り除くだけです。

また、この flag は `execve()` に依存しない privilege change をブロックしない点にも注意してください。たとえば、すでに十分な privilege を持つ task は、`setuid(2)` を直接 call したり、Unix socket 経由で privileged file descriptor を受け取ったりできます。そのため、`no_new_privs` は standalone な回答としてではなく、[seccomp](seccomp.md)、capability sets、namespace exposure と合わせて確認する必要があります。

## Lab

現在の process state を確認します。
```bash
grep NoNewPrivs /proc/self/status
```
runtime が flag を有効にする container と比較してください：
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
強化されたワークロードでは、結果に `NoNewPrivs: 1` と表示されるはずです。

setuid バイナリに対する実際の効果も確認できます：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
`su` が普遍的に exploit 可能だということが比較の要点ではありません。同じ image でも、`execve()` による privilege boundary の越境が依然として許可されているかどうかによって、挙動が大きく異なるということです。

## Security Impact

`no_new_privs` が設定されていない場合、container 内の foothold は、setuid helper や file capabilities を持つ binary を通じて、さらに privilege を上げられる可能性があります。設定されている場合、exec 後のこうした privilege 変更は遮断されます。この影響は、application がそもそも必要としていなかった多くの utility を含む、広範な base image で特に重要です。

seccomp との間にも重要な相互作用があります。非特権 task が filter mode で seccomp filter を install するには、通常、事前に `no_new_privs` を設定する必要があります。これが、hardened container で `Seccomp` と `NoNewPrivs` の両方が有効になっていることが多い理由の一つです。attacker の観点では、両方が確認できる場合、その環境は偶然ではなく意図的に設定されていることを通常意味します。

## Misconfigurations

最も一般的な問題は、互換性がある環境でこの control を有効にしていないことです。Kubernetes では、`allowPrivilegeEscalation` を有効なままにしておくことが、運用上よくある default のミスです。Docker と Podman では、関連する security option を省略すると同じ影響があります。もう一つの recurring failure mode は、container が「privileged ではない」ため、exec 時の privilege transition は自動的に無関係だと思い込むことです。

より subtle な Kubernetes の pitfall として、container が `privileged` である場合、または `CAP_SYS_ADMIN` を持っている場合、`allowPrivilegeEscalation: false` は期待される方法では **honored されません**。Kubernetes API には、これらの場合、`allowPrivilegeEscalation` は実質的に常に true であると記載されています。実際には、この field は最終的な posture における一つの signal として扱うべきであり、runtime の `NoNewPrivs: 1` を保証するものではありません。

## Abuse

`no_new_privs` が設定されていない場合、最初に確認すべきことは、image に privilege を引き上げられる binary がまだ含まれているかどうかです:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
注目すべき結果には、次のものがあります。

- `NoNewPrivs: 0`
- `su`、`mount`、`passwd`、またはディストリビューション固有の管理ツールなどの setuid ヘルパー
- ネットワークまたはファイルシステム権限を付与する file capabilities を持つバイナリ

実際の assessment では、これらの findings だけで escalation が成功することを証明することはできません。しかし、次にテストすべきバイナリを正確に特定できます。

Kubernetes では、YAML の意図が kernel の実際の状態と一致していることも確認します：
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
興味深い組み合わせには、次のようなものがあります。

- Pod spec 内では `allowPrivilegeEscalation: false` だが、コンテナ内では `NoNewPrivs: 0`
- `cap_sys_admin` が存在し、Kubernetes のこのフィールドの信頼性が大幅に低下している
- `Seccomp: 0` と `NoNewPrivs: 0` の組み合わせ。通常、単独のミスではなく、runtime のセキュリティ対策全体が広範に弱体化していることを示す

### setuid によるコンテナ内 privilege escalation の完全な例

この制御は通常、ホストからの脱出を直接防ぐというより、**コンテナ内の privilege escalation** を防ぎます。`NoNewPrivs` が `0` で、setuid helper が存在する場合は、明示的にテストします。
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
既知の setuid バイナリが存在し、機能している場合は、権限移行を維持する方法での起動を試みます。
```bash
/bin/su -c id 2>/dev/null
```
これはそれ自体で container から escape するものではありませんが、container 内の低権限 foothold を container-root に変換できます。これが、mount、runtime socket、または kernel-facing interface を介した後続の host escape の前提条件になることがよくあります。

## Checks

これらの checks の目的は、exec-time の privilege gain がブロックされているかどうか、また、ブロックされていない場合に重要となる helper が image 内にまだ存在するかどうかを確認することです。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
ここで注目すべき点:

- `NoNewPrivs: 1` は通常、より安全な結果です。
- `NoNewPrivs: 0` は、setuid および file-cap ベースの権限昇格経路が依然として関係することを意味します。
- `NoNewPrivs: 1` と `Seccomp: 2` の組み合わせは、より意図的な hardening の姿勢を示す一般的な兆候です。
- Kubernetes manifest で `allowPrivilegeEscalation: false` と指定することは有用ですが、kernel のステータスが ground truth です。
- setuid/file-cap binary がほとんど、またはまったく存在しない minimal image では、`no_new_privs` がない場合でも、attacker に残される post-exploitation の選択肢が少なくなります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効化されていない | `--security-opt no-new-privileges=true` で明示的に有効化します。`dockerd --no-new-privileges` による daemon-wide default も存在します | flag の省略、`--privileged` |
| Podman | デフォルトでは有効化されていない | `--security-opt no-new-privileges` または同等の security configuration で明示的に有効化します | option の省略、`--privileged` |
| Kubernetes | workload policy によって制御される | `allowPrivilegeEscalation: false` はこの効果を要求しますが、`privileged: true` と `CAP_SYS_ADMIN` によって実質的に true のままになります | `allowPrivilegeEscalation: true`、`privileged: true`、`CAP_SYS_ADMIN` の追加 |
| containerd / CRI-O under Kubernetes | Kubernetes workload settings / OCI `process.noNewPrivileges` に従う | 通常は Pod security context から継承され、OCI runtime config に変換されます | Kubernetes の行と同じ |

この protection が存在しないのは、runtime にサポートがないからではなく、単に誰も有効化していないからであることがよくあります。

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
