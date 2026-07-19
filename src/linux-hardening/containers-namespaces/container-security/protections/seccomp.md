# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

**seccomp** は、プロセスが呼び出せる syscall に対して kernel が filter を適用できるようにする mechanism です。container 化された環境では、seccomp は通常 filter mode で使用されます。これにより、プロセスが曖昧な意味で単に「restricted」とマークされるのではなく、具体的な syscall policy の対象になります。これは、多くの container breakout が非常に限定された kernel interface への到達を必要とするため重要です。プロセスが関連する syscall を正常に呼び出せなければ、namespace や capability の細かな検討が関係する前に、多くの攻撃クラスが成立しなくなります。

重要な mental model は単純です。namespace は **プロセスが何を見られるか** を決定し、capability は **プロセスが nominally 試行を許可されている privileged action** を決定し、seccomp は **試行された action の syscall entry point を kernel が受け入れるかどうか** を決定します。これが、capability だけを基準にすると可能に見える攻撃を seccomp が頻繁に防ぐ理由です。

## Security Impact

危険な kernel surface の多くは、比較的少数の syscall を通じてのみ到達できます。container hardening で繰り返し重要になる例として、`mount`、`unshare`、特定の flag を伴う `clone` または `clone3`、`bpf`、`ptrace`、`keyctl`、`perf_event_open` があります。これらの syscall に到達できる attacker は、新しい namespace を作成したり、kernel subsystem を操作したり、通常の application container がまったく必要としない attack surface と interaction したりできる可能性があります。

このため、default runtime seccomp profile は非常に重要です。単なる「追加の defense」ではありません。多くの環境では、kernel functionality の広範な範囲を利用できる container と、application が本当に必要とするものに近い syscall surface に制限された container の違いになります。

## Modes And Filter Construction

seccomp には、歴史的にごく少数の syscall set だけが利用可能な strict mode がありました。しかし、modern container runtime に関係する mode は seccomp filter mode であり、**seccomp-bpf** と呼ばれることもあります。この model では、kernel が filter program を評価し、syscall を allow、errno を返して deny、trap、log、または process を kill するかどうかを決定します。container runtime がこの mechanism を使用するのは、通常の application behavior を許可しながら、危険な syscall の広範な class を block できるだけの表現力があるためです。

2 つの low-level example は、mechanism を魔法のようなものではなく具体的なものとして理解するのに役立ちます。strict mode は、古い「最小限の syscall set だけが残る」model を示します。
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
最後の `open` は、strict mode の最小セットに含まれていないため、プロセスを kill させます。

libseccomp filter の例は、現代的な policy model をより明確に示しています：
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
この形式の policy は、runtime seccomp profiles と聞いて多くの読者が思い浮かべるものです。

## Lab

container 内で seccomp が有効になっていることを確認する簡単な方法は、次のとおりです。
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
デフォルトプロファイルが一般的に制限する操作を試すこともできます:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
コンテナが通常のデフォルト seccomp profile 下で実行されている場合、`unshare` 形式の操作はしばしばブロックされます。これは、image 内に userspace ツールが存在していても、それが必要とする kernel の経路が利用できない場合があることを示す有用なデモです。
コンテナが通常のデフォルト seccomp profile 下で実行されている場合、image 内に userspace ツールが存在していても、`unshare` 形式の操作はしばしばブロックされます。

プロセスのステータスをより一般的に確認するには、次を実行します：
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime Usage

Docker はデフォルトおよびカスタムの seccomp profile をサポートしており、管理者は `--security-opt seccomp=unconfined` を使用して無効化できます。Podman も同様のサポートを提供しており、rootless 実行と seccomp を組み合わせることで、非常に適切なデフォルト設定になることがよくあります。Kubernetes では workload の設定を通じて seccomp を公開しており、通常は `RuntimeDefault` を妥当なベースラインとし、`Unconfined` は単なる利便性のための切り替えではなく、正当な理由を必要とする例外として扱うべきです。

containerd および CRI-O ベースの環境では、正確な経路はより多層的になりますが、原則は同じです。上位の engine または orchestrator が何を実行すべきかを決定し、最終的に runtime がコンテナプロセスに対して結果として得られた seccomp policy をインストールします。結果は、最終的に kernel に到達する runtime の設定に依然として依存します。

### Custom Policy Example

Docker および同様の engine は、JSON からカスタム seccomp profile をロードできます。すべてを許可しながら `chmod` を拒否する最小限の例は、次のようになります。
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
コマンドは `Operation not permitted` で失敗します。これは、その制限が通常のファイル権限だけによるものではなく、syscall policy によるものであることを示しています。実際の hardening では、一般に、緩いデフォルト設定に小規模な blacklist を追加するよりも、allowlist のほうが強力です。

## Misconfigurations

最も大きな間違いは、アプリケーションがデフォルトポリシーで動作しなかったため、seccomp を **unconfined** に設定することです。これはトラブルシューティング中によく行われますが、恒久的な対策としては非常に危険です。filter がなくなると、多くの syscall ベースの breakout primitive に再び到達できるようになります。特に、強力な capability や host namespace の共有も存在する場合は危険です。

もう1つよくある問題は、blog や社内の workaround からコピーした **custom permissive profile** を、慎重にレビューせず使用することです。profile が「アプリケーションが実際に必要とするものだけを許可する」ではなく、「アプリケーションの動作を妨げない」ことを基準に作られているため、危険な syscall のほとんどを残してしまうチームもあります。3つ目の誤解は、non-root container では seccomp の重要性が低いと考えることです。実際には、プロセスが UID 0 でない場合でも、kernel attack surface の多くは依然として関係します。

## Abuse

seccomp が存在しない、または大幅に弱められている場合、攻撃者は namespace-creation syscall を呼び出したり、`bpf` や `perf_event_open` を通じて到達可能な kernel attack surface を拡大したり、`keyctl` を悪用したりできる可能性があります。また、これらの syscall path を `CAP_SYS_ADMIN` のような危険な capability と組み合わせることも可能です。実際の攻撃の多くでは、欠落している control は seccomp だけではありません。しかし、seccomp がないと、privilege model の他の要素が関与する前に危険な syscall を阻止できる数少ない防御の1つが失われるため、exploit path が大幅に短くなります。

最も有用な実践的テストは、通常の default profile が block する正確な syscall family を試すことです。それらが突然動作するなら、container の security posture は大きく変化しています。
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
`CAP_SYS_ADMIN` または別の強力な capability が存在する場合、mount-based abuse の前に seccomp だけが欠けている障壁かどうかをテストします：
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
一部の target では、直ちに full escape を達成することではなく、information gathering と kernel attack surface expansion が目的になります。これらの commands は、特に sensitive な syscall paths に到達可能かどうかを判断するのに役立ちます。
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
seccomp が存在せず、さらに container が他の点でも privileged である場合に、legacy の container-escape ページですでに記載されている、より具体的な breakout techniques へ pivot する意味が生じます。

### 完全な例: `unshare` をブロックしていた唯一のものが seccomp だった場合

多くの target では、seccomp を削除した実際の効果として、namespace の作成や mount の syscall が突然動作し始めます。container に `CAP_SYS_ADMIN` もある場合、次の手順が可能になることがあります。
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
単体ではまだ host escape ではありませんが、これは mount 関連の exploitation を妨げていた barrier が seccomp だったことを示しています。

### 完全な例: seccomp 無効 + cgroup v1 `release_agent`

seccomp が無効で、container が cgroup v1 hierarchy を mount できる場合、cgroups セクションの `release_agent` technique に到達可能になります:
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
これは seccomp-only exploit ではありません。重要なのは、seccomp が unconfined になると、以前はブロックされていた syscall-heavy な breakout chain が、記述どおりに動作し始める可能性があるという点です。

## Checks

これらのチェックの目的は、seccomp がそもそも有効かどうか、`no_new_privs` が seccomp とともに設定されているかどうか、そして runtime configuration で seccomp が明示的に無効化されているかどうかを確認することです。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
ここで注目すべき点:

- `Seccomp` の値が 0 以外であれば filtering が有効です。通常、`0` は seccomp 保護がないことを意味します。
- Runtime security options に `seccomp=unconfined` が含まれている場合、workload は最も有用な syscall-level defenses の 1 つを失っています。
- `NoNewPrivs` は seccomp そのものではありませんが、両方が設定されている場合は、どちらも設定されていない場合よりも、通常はより慎重な hardening posture を示します。

container にすでに suspicious mounts、broad capabilities、または shared host namespaces があり、さらに seccomp も unconfined である場合、その組み合わせは major escalation signal として扱うべきです。container を直ちに breakable できるとは限りませんが、attacker が利用できる kernel entry points の数は大幅に増加しています。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | 通常はデフォルトで有効 | override されない限り、Docker 組み込みの default seccomp profile を使用 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=/path/profile.json`、`--privileged` |
| Podman | 通常はデフォルトで有効 | override されない限り、runtime default seccomp profile を適用 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=profile.json`、`--seccomp-policy=image`、`--privileged` |
| Kubernetes | **デフォルトで保証されない** | `securityContext.seccompProfile` が未設定の場合、kubelet で `--seccomp-default` が有効化されていなければデフォルトは `Unconfined`。それ以外では `RuntimeDefault` または `Localhost` を明示的に設定する必要がある | `securityContext.seccompProfile.type: Unconfined`、`seccompDefault` がない cluster で seccomp を未設定のままにする、`privileged: true` |
| Kubernetes 配下の containerd / CRI-O | Kubernetes の node および Pod の設定に従う | Kubernetes が `RuntimeDefault` を要求した場合、または kubelet の seccomp defaulting が有効な場合に runtime profile を使用 | Kubernetes の行と同じ。直接の CRI/OCI configuration で seccomp を完全に省略することも可能 |

Kubernetes の動作は、operators を最も驚かせるものです。多くの cluster では、Pod が seccomp を要求するか、kubelet が `RuntimeDefault` をデフォルトにするよう設定されていない限り、seccomp は依然として適用されません。
{{#include ../../../../banners/hacktricks-training.md}}
