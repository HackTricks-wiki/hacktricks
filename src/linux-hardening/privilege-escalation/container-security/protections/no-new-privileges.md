# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` は、プロセスが `execve()` をまたいでより高い権限を取得するのを防ぐ kernel hardening 機能です。実用上は、このフラグが設定されると、setuid binary、setgid binary、または Linux file capabilities を持つ file を実行しても、プロセスがすでに持っていた権限を超える追加権限は得られません。containerized environments ではこれは重要です。なぜなら、多くの privilege-escalation chains は、起動時に権限を変更する executable が image 内にあることを見つけることに依存しているからです。

防御の観点では、`no_new_privs` は namespaces、seccomp、または capability dropping の代替ではありません。これは補強層です。すでに code execution を得た後の、特定の種類の後続の escalation をブロックします。そのため、image に helper binaries、package-manager artifacts、または legacy tools が含まれていて、それらが partial compromise と組み合わさると危険になりうる環境で特に有用です。

## Operation

この挙動の背後にある kernel flag は `PR_SET_NO_NEW_PRIVS` です。プロセスに一度設定されると、後続の `execve()` 呼び出しでは権限を増やせません。重要なのは、プロセスは binary を実行し続けられるという点です。ただし、kernel が通常なら許可する privilege boundary を、その binary を使って越えることはできません。

kernel の挙動は **継承され、かつ元に戻せません**。一度 task が `no_new_privs` を設定すると、その bit は `fork()`、`clone()`、`execve()` をまたいで継承され、後から解除できません。これは assessment で役立ちます。container process に `NoNewPrivs: 1` が 1 つでもあれば、完全に別の process tree を見ていない限り、その子孫も通常は同じ mode のままであるべきだと考えられます。

Kubernetes-oriented environments では、`allowPrivilegeEscalation: false` が container process に対してこの挙動に対応します。Docker や Podman style runtimes では、同等の設定は通常 security option を通じて明示的に有効化されます。OCI layer では、同じ概念が `process.noNewPrivileges` として表れます。

## Important Nuances

`no_new_privs` は **exec-time** の privilege gain をブロックしますが、すべての privilege change を止めるわけではありません。特に:

- setuid と setgid の遷移は `execve()` をまたいで機能しなくなる
- file capabilities は `execve()` 時に permitted set に追加されない
- AppArmor や SELinux のような LSMs は `execve()` 後に制約を緩めない
- すでに持っている privilege は、引き続きすでに持っている privilege のまま

最後の点は運用上重要です。プロセスがすでに root として動作している、すでに危険な capability を持っている、または強力な runtime API や書き込み可能な host mount へのアクセスをすでに持っている場合、`no_new_privs` を設定してもそれらの露出は無効化されません。これは、権限昇格チェーンにおける一般的な **next step** を 1 つ取り除くだけです。

また、このフラグは `execve()` に依存しない privilege change はブロックしません。たとえば、すでに十分に privileged な task は、`setuid(2)` を直接呼び出したり、Unix socket 経由で privileged file descriptor を受け取ったりできます。だからこそ `no_new_privs` は、単独の答えとしてではなく、[seccomp](seccomp.md)、capability sets、namespace exposure と合わせて読むべきです。

## Lab

現在の process state を確認します:
```bash
grep NoNewPrivs /proc/self/status
```
ランタイムがフラグを有効にしているコンテナと比較すると:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
強化された workload では、結果に `NoNewPrivs: 1` が表示されるはずです。

また、setuid binary に対する実際の効果も確認できます:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
この比較の要点は、`su` が普遍的に悪用可能だということではない。同じ image でも、`execve()` がまだ privilege boundary を越えられるかどうかで、挙動が大きく変わり得るということだ。

## Security Impact

`no_new_privs` がない場合、container 内の foothold は、setuid helper や file capabilities を持つ binaries を通じて、なおも昇格できる可能性がある。これが存在する場合、こうした post-exec の privilege 変更は遮断される。この効果は、アプリケーションがそもそも必要としていなかった多くの utilities を含む大きな base images で特に重要になる。

重要な seccomp の相互作用もある。unprivileged tasks は一般に、filter mode で seccomp filter を install する前に `no_new_privs` を set する必要がある。これが、hardended containers で `Seccomp` と `NoNewPrivs` が一緒に有効になっていることが多い理由の一つだ。攻撃者の観点では、両方が見えるということは、たいてい環境が偶然ではなく意図的に構成されたことを意味する。

## Misconfigurations

最も一般的な問題は、互換性があるはずの環境でこの control を有効にしないことだ。Kubernetes では、`allowPrivilegeEscalation` を有効のままにしてしまうのが、よくある運用ミスだ。Docker や Podman でも、該当する security option を省略すれば同じ結果になる。もう一つ繰り返し起きる失敗は、container が "not privileged" だからといって、exec-time の privilege transition は自動的に無関係だと思い込むことだ。

より subtle な Kubernetes の落とし穴として、container が `privileged` である場合や `CAP_SYS_ADMIN` を持つ場合には、`allowPrivilegeEscalation: false` は人々が期待するようには **適用されない**。Kubernetes API は、そうしたケースでは `allowPrivilegeEscalation` が事実上常に true であると document している。実際には、この field は最終的な posture を判断するための一つの signal として扱うべきであり、runtime が最終的に `NoNewPrivs: 1` になったことを保証するものではない。

## Abuse

`no_new_privs` が set されていない場合、最初に確認すべきなのは、まだ privilege を上げられる binaries が image に含まれているかどうかだ:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
興味深い結果には以下が含まれます:

- `NoNewPrivs: 0`
- `su`、`mount`、`passwd`、またはディストリビューション固有の管理ツールのような setuid helper
- ネットワークまたはファイルシステム権限を付与する file capabilities を持つ binaries

実際の assessment では、これらの findings だけで動作する escalation を証明することはできませんが、次に test すべき binaries を正確に特定できます。

Kubernetes では、YAML の intent が kernel reality と一致していることも確認してください:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
興味深い組み合わせには以下が含まれます:

- Pod spec では `allowPrivilegeEscalation: false` だが、container では `NoNewPrivs: 0`
- `cap_sys_admin` が存在し、これにより Kubernetes のフィールドはかなり信頼性が低くなる
- `Seccomp: 0` と `NoNewPrivs: 0` で、これは通常、単一の孤立したミスというより、runtime 全体の防御姿勢が広く弱められていることを示す

### Full Example: In-Container Privilege Escalation Through setuid

この制御は通常、host escape を直接防ぐというより、**in-container privilege escalation** を防ぎます。`NoNewPrivs` が `0` で、setuid helper が存在する場合は、明示的にテストしてください:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
既知のsetuidバイナリが存在して機能する場合、権限移行を維持する形で起動してみてください:
```bash
/bin/su -c id 2>/dev/null
```
これはそれ自体ではコンテナからの脱出にはなりませんが、コンテナ内の低権限の foothold を container-root に変えられることがあります。これは、mount、runtime sockets、または kernel-facing interfaces を通じた後続の host escape の前提条件になることがよくあります。

## Checks

これらの checks の目的は、実行時の権限昇格がブロックされているかどうか、また、そうでない場合に重要となる helper が image にまだ含まれているかどうかを確認することです。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
ここで興味深いのは:

- `NoNewPrivs: 1` は通常、より安全な結果です。
- `NoNewPrivs: 0` は、setuid と file-cap ベースの権限昇格パスが依然として有効であることを意味します。
- `NoNewPrivs: 1` に加えて `Seccomp: 2` があるのは、より意図的な hardening posture の一般的な兆候です。
- `allowPrivilegeEscalation: false` と書かれた Kubernetes manifest は有用ですが、kernel の status が ground truth です。
- setuid/file-cap バイナリが少ない、または存在しない minimal image は、`no_new_privs` が欠けていても attacker に post-exploitation の選択肢を少なくします。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効化されていない | `--security-opt no-new-privileges=true` で明示的に有効化される; daemon-wide default も `dockerd --no-new-privileges` で存在する | flag を省略する, `--privileged` |
| Podman | デフォルトでは有効化されていない | `--security-opt no-new-privileges` もしくは同等の security configuration で明示的に有効化される | option を省略する, `--privileged` |
| Kubernetes | workload policy によって制御される | `allowPrivilegeEscalation: false` はその効果を要求するが、`privileged: true` と `CAP_SYS_ADMIN` は実質的に true のままにする | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` を追加する |
| containerd / CRI-O under Kubernetes | Kubernetes の workload settings / OCI `process.noNewPrivileges` に従う | 通常は Pod の security context から継承され、OCI runtime config に変換される | Kubernetes の行と同じ |

この protection は、runtime がサポートしていないからではなく、単に誰も有効化していないという理由で欠けていることがよくあります。

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
