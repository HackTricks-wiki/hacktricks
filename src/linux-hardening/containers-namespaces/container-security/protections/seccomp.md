# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

**seccomp** は、プロセスが呼び出せる syscall に対してカーネルがフィルターを適用できるようにする仕組みです。コンテナ化された環境では、通常、プロセスを曖昧な意味で単に「restricted」とマークするのではなく、具体的な syscall ポリシーの対象にするため、フィルターモードで seccomp が使用されます。これは、多くのコンテナ breakout が、非常に特定のカーネルインターフェースへの到達を必要とするため重要です。プロセスが関連する syscall を正常に呼び出せなければ、namespace や capability の細かな問題を検討する以前に、多くの攻撃クラスが排除されます。

基本的な mental model はシンプルです。namespace は **プロセスが何を見られるか** を決定し、capability は **プロセスが名目上どの privileged action を試行できるか** を決定し、seccomp は **試行された action に対応する syscall のエントリーポイントをカーネルが受け入れるかどうか** を決定します。そのため、seccomp は capability だけを見ると可能に見える攻撃を、頻繁に防止します。

## セキュリティへの影響

危険なカーネルサーフェスの多くは、比較的少数の syscall セットを通じてのみ到達可能です。コンテナの hardening で繰り返し重要になる例としては、`mount`、`unshare`、特定の flag を指定した `clone` や `clone3`、`bpf`、`ptrace`、`keyctl`、`perf_event_open` などがあります。これらの syscall に到達できる攻撃者は、新しい namespace の作成、カーネルサブシステムの操作、または通常の application container がまったく必要としない attack surface との相互作用を行える可能性があります。

これが、デフォルトの runtime seccomp profile が非常に重要である理由です。これは単なる「追加の防御」ではありません。多くの環境では、コンテナがカーネル機能の広範な部分を利用できる状態と、アプリケーションが本当に必要とするものに近い syscall surface に制限される状態との違いになります。

## モードとフィルターの構築

seccomp には、歴史的にごく少数の syscall セットのみが利用可能な strict mode がありました。しかし、modern container runtime に関係するモードは seccomp filter mode であり、しばしば **seccomp-bpf** と呼ばれます。このモデルでは、カーネルが filter program を評価し、syscall を許可するか、errno を返して拒否するか、trap するか、ログに記録するか、プロセスを kill するかを決定します。<sup>[[1]](#references)</sup> Container runtime がこの仕組みを使用するのは、通常の application behavior を許可しながら、危険な syscall の広範なクラスを block できるだけの表現力があるためです。

2 つの low-level example は、仕組みを抽象的なものではなく具体的に理解するうえで役立ちます。strict mode は、古い「最小限の syscall セットだけが残る」モデルを示します。
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
最後の `open` によってプロセスが kill されます。これは strict mode の最小セットに含まれていないためです。

libseccomp filter の例を見ると、modern policy model がより明確に分かります。
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
この形式のポリシーは、runtime seccomp profilesについて考えるときに、ほとんどの読者が思い浮かべるものです。

## Lab

container内でseccompが有効になっていることを確認する簡単な方法は次のとおりです:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
default profiles が一般的に制限する操作も試せます:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
コンテナが通常のデフォルト seccomp プロファイルの下で実行されている場合、`unshare` スタイルの操作はしばしばブロックされます。これは、イメージ内に userspace ツールが存在していても、それが必要とするカーネルパスが利用できない可能性があることを示す有用なデモンストレーションです。
コンテナが通常のデフォルト seccomp プロファイルの下で実行されている場合、イメージ内に userspace ツールが存在していても、`unshare` スタイルの操作はしばしばブロックされます。

プロセスのステータスをより一般的に確認するには、次を実行します:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime Usage

Docker はデフォルトおよびカスタムの seccomp プロファイルをサポートしており、管理者は `--security-opt seccomp=unconfined` を使って無効化できます。<sup>[[2]](#references)</sup> Podman も同様にサポートしており、rootless 実行と seccomp を組み合わせることで、非常に適切なデフォルト設定になることがよくあります。Kubernetes では workload の設定を通じて seccomp を公開しており、通常は `RuntimeDefault` が妥当なベースラインです。一方、`Unconfined` は利便性のための切り替えではなく、正当な理由を必要とする例外として扱うべきです。<sup>[[3]](#references)</sup>

containerd および CRI-O ベースの環境では、正確な経路はより多層的になりますが、原則は同じです。高レベルの engine または orchestrator がどう動作すべきかを決定し、最終的に runtime がその結果として得られた seccomp ポリシーをコンテナプロセスに設定します。結果は、最終的に kernel に到達する runtime 設定に依存します。

### Custom Policy Example

Docker および同様の engine は、JSON からカスタム seccomp プロファイルを読み込めます。`chmod` を拒否し、それ以外をすべて許可する最小限の例は次のようになります。
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
適用対象:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
コマンドは `Operation not permitted` で失敗します。これは、その制限が通常のファイル権限だけではなく、syscall policy によるものであることを示しています。実際の hardening では、一般に、限定的な blacklist を含む permissive なデフォルト設定よりも allowlists のほうが強力です。

## Misconfigurations

最も無謀なミスは、アプリケーションがデフォルトの policy で動作しなかったという理由で、seccomp を **unconfined** に設定することです。これは troubleshooting 中によく行われますが、恒久的な修正としては非常に危険です。filter がなくなると、特に強力な capabilities や host namespace sharing も存在する場合に、多くの syscall-based breakout primitives に再び到達できるようになります。

もう1つ頻発する問題は、blog や社内の workaround からコピーした **custom permissive profile** を、慎重に review せず使用することです。チームが「アプリケーションが壊れないようにする」ことを目的として profile を構築し、「アプリケーションが実際に必要とするものだけを許可する」ことを目的にしていないため、危険な syscall のほぼすべてを残してしまうことがあります。3つ目の誤解は、non-root containers では seccomp の重要性が低いと考えることです。実際には、process が UID 0 でない場合でも、kernel attack surface の多くは依然として関連します。

## Abuse

seccomp が存在しないか、大幅に弱められている場合、attacker は namespace-creation syscalls を呼び出したり、`bpf` や `perf_event_open` によって到達可能な kernel attack surface を拡大したり、`keyctl` を abuse したり、これらの syscall paths を `CAP_SYS_ADMIN` のような危険な capabilities と組み合わせたりできる可能性があります。多くの実際の攻撃では、seccomp だけが欠落している control ではありません。しかし、その欠如によって exploit path が大幅に短縮されます。これは、privilege model の他の部分が関与する前に、risk のある syscall を阻止できる数少ない defenses の1つが失われるためです。

最も有用な実践的テストは、default profiles が通常 block する正確な syscall families を試すことです。それらが突然動作するなら、container posture は大きく変化しています。
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
`CAP_SYS_ADMIN` またはその他の強力な capability が存在する場合は、mount-based abuse の前に残っている障壁が seccomp だけかどうかをテストします：
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
一部のターゲットでは、直ちに完全な escape を達成することではなく、情報収集と kernel の attack surface の拡大が目的になります。これらのコマンドは、特に機密性の高い syscall path に到達可能かどうかを判断するのに役立ちます。
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
seccomp が存在せず、コンテナが他の点でも privileged である場合に限り、legacy container-escape pages に既に記載されている、より具体的な breakout techniques へ pivot する意味があります。

### Full Example: seccomp Was The Only Thing Blocking `unshare`

多くの target では、seccomp を削除することによる実質的な効果は、namespace-creation または mount syscall が突然機能し始めることです。コンテナに `CAP_SYS_ADMIN` もある場合、次の sequence が可能になることがあります:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
これ単体ではまだ host escape ではありませんが、mount 関連の exploitation を阻止していた barrier が seccomp であったことを示しています。

### Full Example: seccomp Disabled + cgroup v1 `release_agent`

seccomp が disabled で、container から cgroup v1 hierarchy を mount できる場合、cgroups セクションの `release_agent` technique に到達可能になります：
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
これは seccomp-only exploit ではありません。要点は、seccomp が unconfined になると、以前はブロックされていた syscall-heavy な breakout chain が、記述どおりに動作し始める可能性があるということです。

## チェック

これらのチェックの目的は、seccomp がそもそも有効かどうか、`no_new_privs` が seccomp と併用されているかどうか、そして runtime configuration で seccomp が明示的に無効化されているかどうかを確認することです。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
ここで注目すべき点：

- `Seccomp` の値が 0 以外であれば filtering が有効であることを意味し、`0` は通常、seccomp による保護がないことを意味します。
- runtime security options に `seccomp=unconfined` が含まれている場合、workload は最も有用な syscall-level defenses の 1 つを失っています。
- `NoNewPrivs` 自体は seccomp ではありませんが、両方が設定されている場合は、どちらも設定されていない場合よりも、通常はより慎重な hardening posture を示します。

container にすでに suspicious mounts、broad capabilities、または shared host namespaces があり、さらに seccomp も unconfined である場合、その組み合わせは major escalation signal として扱うべきです。container が直ちに breakable になるとは限りませんが、attacker が利用できる kernel entry points の数は大幅に増加しています。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 通常はデフォルトで有効 | override されない限り、Docker built-in default seccomp profile を使用 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=/path/profile.json`、`--privileged` |
| Podman | 通常はデフォルトで有効 | override されない限り、runtime default seccomp profile を適用 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=profile.json`、`--seccomp-policy=image`、`--privileged` |
| Kubernetes | **デフォルトで保証されていない** | `securityContext.seccompProfile` が未設定の場合、kubelet が `--seccomp-default` を有効にしていなければ、default は `Unconfined` です。それ以外の場合は `RuntimeDefault` または `Localhost` を明示的に設定する必要があります | `securityContext.seccompProfile.type: Unconfined`、`seccompDefault` がない cluster で seccomp を未設定のままにする、`privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node と Pod の settings に従う | Kubernetes が `RuntimeDefault` を要求した場合、または kubelet の seccomp defaulting が有効な場合に runtime profile を使用 | Kubernetes の行と同じ。direct CRI/OCI configuration によって seccomp を完全に省略することも可能 |

Kubernetes の behavior は、operator を最も驚かせることが多い点です。多くの cluster では、Pod が seccomp を要求するか、kubelet が `RuntimeDefault` を default にするよう設定されていない限り、seccomp は依然として存在しません。<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
