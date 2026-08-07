# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` は、`execve()` をまたいでプロセスがより高い privilege を獲得するのを防ぐ kernel hardening 機能です。実際には、この flag が設定されると、setuid binary、setgid binary、または Linux file capabilities を持つ file を実行しても、プロセスがすでに持っていた privilege を超える追加の privilege は付与されません。containerized 環境では、多くの privilege-escalation chain が、起動時に privilege を変更する executable を image 内から探すことに依存しているため、これは重要です。

defensive な観点では、`no_new_privs` は namespace、seccomp、または capability dropping の代替ではありません。これは補強レイヤーです。コード実行をすでに取得した後に行われる、特定の follow-up escalation をブロックします。そのため、helper binary、package-manager artifact、または legacy tool を含む image が、部分的な compromise と組み合わさると危険になる環境で特に有用です。

## 動作

この動作の背後にある kernel flag は `PR_SET_NO_NEW_PRIVS` です。プロセスに対して一度設定されると、それ以降の `execve()` 呼び出しで privilege を増加させることはできません。重要なのは、プロセスが引き続き binary を実行できる点です。ただし、その binary を使って、kernel が通常なら認める privilege boundary を越えることはできません。<sup>[[1]](#references)</sup>

kernel の動作は **継承され、元に戻せません**。task が一度 `no_new_privs` を設定すると、その bit は `fork()`、`clone()`、`execve()` をまたいで継承され、後から unset することはできません。<sup>[[1]](#references)</sup> これは assessment で有用です。container process に `NoNewPrivs: 1` が 1 つ設定されていれば、まったく別の process tree を調べているのでない限り、通常は descendant もこの mode を維持することを意味します。

Kubernetes 指向の環境では、`allowPrivilegeEscalation: false` が container process に対してこの動作に対応します。<sup>[[2]](#references)</sup> Docker および Podman style の runtime では、通常、security option を通じて明示的に有効化します。OCI layer では、同じ概念が `process.noNewPrivileges` として現れます。

## 重要な注意点

`no_new_privs` は **exec-time** の privilege gain をブロックしますが、あらゆる privilege change をブロックするわけではありません。<sup>[[1]](#references)</sup> 特に、以下のとおりです。

- setuid および setgid の transition は `execve()` をまたいで機能しなくなる
- file capabilities は `execve()` 時に permitted set へ追加されない
- AppArmor や SELinux などの LSM は `execve()` 後に constraint を緩和しない
- すでに保持している privilege は、引き続き保持される

最後の点は、運用上重要です。プロセスがすでに root として実行されている場合、すでに危険な capability を持っている場合、または強力な runtime API や writable host mount にすでにアクセスできる場合、`no_new_privs` を設定しても、それらの exposure が無効になるわけではありません。これは privilege-escalation chain における、よくある **次の step** を 1 つ取り除くだけです。

また、この flag は `execve()` に依存しない privilege change をブロックしない点にも注意してください。<sup>[[1]](#references)</sup> たとえば、すでに十分な privilege を持つ task は、`setuid(2)` を直接呼び出したり、Unix socket 経由で privileged file descriptor を受け取ったりできる場合があります。このため、`no_new_privs` は単独の答えとしてではなく、[seccomp](seccomp.md)、capability set、namespace exposure と併せて確認すべきです。

## Lab

現在の process state を確認します。
```bash
grep NoNewPrivs /proc/self/status
```
runtime が flag を有効にする container と比較してください:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
強化された workload では、結果に `NoNewPrivs: 1` と表示されるはずです。

setuid binary に対する実際の効果も、次のように確認できます。
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
`su` が普遍的に exploit 可能だということが比較の要点ではありません。同じ image でも、`execve()` による privilege boundary の越境が引き続き許可されているかどうかによって、挙動が大きく異なるということです。

## Security Impact

`no_new_privs` が存在しない場合、container 内の foothold は、setuid helper や file capabilities を持つ binary を通じて、さらに privilege を昇格できる可能性があります。存在する場合、exec 後の privilege 変更は遮断されます。この効果は、application が本来必要としていなかった多くの utility を含む、幅広い base image において特に重要です。

seccomp との相互作用も重要です。Unprivileged task が filter mode で seccomp filter を install するには、通常、事前に `no_new_privs` を設定する必要があります。<sup>[[1]](#references)</sup> これが、hardened container で `Seccomp` と `NoNewPrivs` の両方が有効になっていることが多い理由の一つです。attacker の視点では、通常この両方が表示されていれば、environment が偶然ではなく意図的に設定されたことを意味します。

## Misconfigurations

最も一般的な問題は、control と互換性がある environment で、単にこれを有効化していないことです。Kubernetes では、`allowPrivilegeEscalation` を有効なままにしておくことが、運用上よくあるデフォルトのミスです。Docker と Podman では、関連する security option を省略すると同じ効果になります。もう一つの繰り返し発生する failure mode は、container が「privileged ではない」ため、exec 時の privilege transition は自動的に無関係になると思い込むことです。

より subtle な Kubernetes の pitfall として、container が `privileged` である場合、または `CAP_SYS_ADMIN` を持っている場合、`allowPrivilegeEscalation: false` は期待される形では **honored されません**。Kubernetes API では、これらの場合、`allowPrivilegeEscalation` は実質的に常に true であると document されています。<sup>[[2]](#references)</sup> 実際には、これは field を最終的な posture における一つの signal として扱うべきであり、runtime が最終的に `NoNewPrivs: 1` になったことを保証するものではないという意味です。

## Abuse

`no_new_privs` が設定されていない場合、最初に確認すべきことは、image に privilege を引き上げられる binary がまだ含まれているかどうかです：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
興味深い結果には、以下が含まれます。

- `NoNewPrivs: 0`
- `su`、`mount`、`passwd`、またはディストリビューション固有の管理ツールなどの setuid helpers
- network または filesystem privileges を付与する file capabilities を持つ binaries

実際の assessment では、これらの findings だけで escalation が機能することを証明するものではありません。しかし、次に testing する価値がある binaries を正確に特定できます。

Kubernetes では、YAML の意図が kernel の実際の状態と一致していることも verify します：
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
興味深い組み合わせには、次のようなものがあります。

- Pod spec では `allowPrivilegeEscalation: false` だが、container 内では `NoNewPrivs: 0`
- `cap_sys_admin` が存在しており、Kubernetes の field の信頼性が大幅に低下している
- `Seccomp: 0` と `NoNewPrivs: 0` の組み合わせ。通常、単一の孤立したミスではなく、runtime の security posture が広範に弱体化していることを示す

### 完全な例: setuid による In-Container Privilege Escalation

この control は通常、host escape を直接防ぐものではなく、**in-container privilege escalation** を防ぎます。`NoNewPrivs` が `0` で、setuid helper が存在する場合は、明示的にテストします。
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
既知の setuid バイナリが存在し、正常に機能している場合は、権限遷移を維持する方法での起動を試みます。
```bash
/bin/su -c id 2>/dev/null
```
これは、それ自体でコンテナから脱出するものではありません。しかし、コンテナ内の低権限 foothold を container-root に変換できます。これが、mount、runtime socket、または kernel-facing interface を介して後続のホスト脱出を行う際の前提条件になることがよくあります。

## チェック

これらのチェックの目的は、exec-time の privilege gain がブロックされているかどうか、またブロックされていない場合に影響を及ぼす可能性のある helpers がイメージ内に残っているかどうかを確認することです。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
ここで興味深い点:

- `NoNewPrivs: 1` は通常、より安全な結果です。
- `NoNewPrivs: 0` は、setuid および file-cap ベースの escalation paths が依然として関係することを意味します。
- `NoNewPrivs: 1` と `Seccomp: 2` の組み合わせは、より意図的な hardening posture の一般的な兆候です。
- `allowPrivilegeEscalation: false` と記載された Kubernetes manifest は有用ですが、kernel status が ground truth です。
- setuid/file-cap binaries がほとんどない、またはまったくない minimal image では、`no_new_privs` が欠落していても、attacker の post-exploitation options は少なくなります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効化されていない | `--security-opt no-new-privileges=true` で明示的に有効化。`dockerd --no-new-privileges` による daemon-wide default も存在 | flag を省略、`--privileged` |
| Podman | デフォルトでは有効化されていない | `--security-opt no-new-privileges` または同等の security configuration で明示的に有効化 | option を省略、`--privileged` |
| Kubernetes | workload policy により制御 | `allowPrivilegeEscalation: false` はこの効果を要求しますが、`privileged: true` と `CAP_SYS_ADMIN` により実質的に true のままになります | `allowPrivilegeEscalation: true`、`privileged: true`、`CAP_SYS_ADMIN` の追加 |
| containerd / CRI-O under Kubernetes | Kubernetes workload settings / OCI `process.noNewPrivileges` に従う | 通常は Pod security context から継承され、OCI runtime config に変換されます | Kubernetes の行と同じ |

この protection が存在しないのは、runtime にサポートがないからではなく、単に誰も有効化していないためであることが多いです。

## References

- [1] [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
