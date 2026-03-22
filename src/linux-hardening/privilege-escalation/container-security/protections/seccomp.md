# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

**seccomp** はプロセスが呼び出せる syscalls に対して kernel がフィルタを適用する仕組みです。コンテナ化された環境では、seccomp は通常 filter mode で使用され、プロセスが漠然と「restricted」とマークされるだけでなく、具体的な syscall ポリシーが適用されます。これは多くのコンテナ脱出が非常に特定の kernel インターフェースに到達することを要求するため重要です。プロセスが関連する syscalls を正常に呼び出せない場合、namespace や capability の細かな違いが問題になる前に、多くの攻撃クラスが消滅します。

基本的な考え方は単純です: namespaces は **プロセスが何を見られるか (what the process can see)** を決め、capabilities は **プロセスが名目上試みることを許可されている特権アクションは何か (which privileged actions the process is nominally allowed to attempt)** を決め、seccomp は **カーネルが試行中のアクションの syscall エントリポイントを受け入れるかどうか (whether the kernel will even accept the syscall entry point for the attempted action)** を決めます。このため、seccomp はしばしば capabilities のみを見て可能に見える攻撃を阻止します。

## セキュリティへの影響

多くの危険な kernel サーフェスは、比較的小さな syscall の集合を通じてしか到達できません。コンテナのハードニングで繰り返し重要になる例には `mount`、`unshare`、特定のフラグ付きの `clone` または `clone3`、`bpf`、`ptrace`、`keyctl`、および `perf_event_open` があります。これらの syscalls に到達できる攻撃者は、新しい namespaces を作成したり、kernel のサブシステムを操作したり、通常のアプリケーションコンテナには不要な攻撃対象に対して相互作用したりできる可能性があります。

これがデフォルトの runtime seccomp プロファイルが非常に重要な理由です。それらは単なる「追加の防御」ではありません。多くの環境では、コンテナが kernel の広範な機能を行使できるか、アプリケーションが本当に必要とするものにより近い syscall 面に制約されるかの違いを生みます。

## モードとフィルターの構築

seccomp には歴史的にごく少数の syscall のみが利用可能になる strict mode がありましたが、現代のコンテナランタイムに関係するモードは seccomp filter mode、しばしば **seccomp-bpf** と呼ばれるものです。このモデルでは、kernel がフィルタプログラムを評価し、ある syscall を許可するか、errno を返して拒否するか、trapped にするか、logged にするか、あるいはプロセスを kill するかを決定します。Container runtimes はこの仕組みを使用します。これは通常のアプリケーション動作を許容しつつ、危険な syscalls の広範なクラスをブロックするのに十分表現力があるためです。

仕組みを魔法ではなく具体的にするために、2 つの低レベルの例が有用です。Strict mode は古い「ごく最小の syscall 集合だけが生き残る」モデルを示します:
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
最後の `open` は strict mode の最小セットに含まれていないため、プロセスが強制終了されます。

libseccomp フィルタの例は、現代のポリシーモデルをより明確に示します:
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
この種のポリシーは、ほとんどの読者がruntime seccomp profilesを思い浮かべるときに想像するものです。

## Lab

コンテナでseccompが有効になっていることを簡単に確認する方法は次のとおりです:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
また、default profiles が一般に制限する操作を試すこともできます:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
コンテナが通常のデフォルト seccomp profile の下で実行されている場合、`unshare` スタイルの操作はしばしばブロックされます。これは、userspace tool がイメージ内に存在していても、必要とする kernel path が利用できない場合があることを示す有用なデモンストレーションです。

コンテナが通常のデフォルト seccomp profile の下で実行されている場合、`unshare` スタイルの操作は、userspace tool がイメージ内に存在している場合でもしばしばブロックされます。

プロセスの状態をより一般的に確認するには、次を実行してください:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## ランタイムでの使用

Dockerはデフォルトとカスタムのseccompプロファイルの両方をサポートし、管理者は`--security-opt seccomp=unconfined`でこれらを無効化できる。Podmanも同様のサポートがあり、seccompをrootless実行と組み合わせて非常に妥当なデフォルト姿勢をとることが多い。Kubernetesはワークロード設定を通じてseccompを公開しており、`RuntimeDefault`は通常妥当なベースラインであり、`Unconfined`は利便性のためのトグルではなく正当化を要する例外として扱うべきだ。

containerdやCRI-Oベースの環境では実際の経路はより階層化されるが、原則は同じである：上位のエンジンやオーケストレータが何を行うかを決定し、ランタイムが最終的にコンテナプロセスに対して結果のseccompポリシーを導入する。結果はカーネルに到達する最終的なランタイム設定に依存する。

### カスタムポリシーの例

DockerなどのエンジンはJSONからカスタムseccompプロファイルを読み込める。その他をすべて許可しつつ`chmod`を拒否する最小の例は次のとおり:
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
使用ツール：
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
コマンドは `Operation not permitted` で失敗し、制限が単なるファイル権限ではなく syscall ポリシーによるものであることを示している。実際のハードニングでは、allowlists は一般に、少数の blacklist を用いた寛容なデフォルトよりも強力である。

## 誤設定

最も粗いミスは、アプリケーションがデフォルトポリシー下で失敗したために seccomp を **unconfined** に設定してしまうことだ。これはトラブルシューティング時によく見られ、恒久的な対処としては非常に危険である。フィルタがなくなると、多くの syscall ベースの脱出プリミティブが再び到達可能になり、特に強力な capabilities やホスト namespace の共有がある場合にはその危険性が高まる。

別の頻繁に起きる問題は、ブログや社内の回避策からコピーした **custom permissive profile** を十分にレビューせずに使うことである。チームはしばしばプロファイルが「アプリを止めない」ために作られているため、実際に必要なものだけを許可するのではなく、ほとんどすべての危険な syscall を残してしまうことがある。三つ目の誤解は、非 root コンテナでは seccomp の重要性が低いと考えることである。実際には、プロセスが UID 0 でない場合でも多くのカーネル攻撃面が依然として関連する。

## 悪用

seccomp が存在しないか著しく弱められていると、攻撃者は namespace 作成を行う syscall を呼び出したり、`bpf` や `perf_event_open` を通じて到達可能なカーネル攻撃面を拡張したり、`keyctl` を悪用したり、これらの syscall 経路を `CAP_SYS_ADMIN` のような危険な capabilities と組み合わせたりする可能性がある。多くの実際の攻撃では、seccomp が唯一の欠けている制御ではないが、その不在はエクスプロイト経路を劇的に短くする。なぜなら、それがリスクのある syscall を、残りの特権モデルが作用する前に阻止できる数少ない防御の一つを除去してしまうからである。

最も有用な実践的テストは、デフォルトプロファイルが通常ブロックする正確な syscall ファミリを試すことである。もしそれらが突然動作するなら、コンテナの姿勢は大きく変わっている：
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
もし `CAP_SYS_ADMIN` または別の強力な capability が存在する場合、mount-based abuse の前に seccomp が唯一欠けている障壁かどうかをテストする:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
一部のターゲットでは、即座の目的が完全な escape ではなく、情報収集や kernel attack-surface の拡大であることがある。これらのコマンドは、特に敏感な syscall パスに到達可能かどうかを判断するのに役立つ：
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
seccomp が無効で、コンテナが他の点でも特権化されている場合、既に legacy container-escape ページに記載されているより具体的なブレイクアウト手法へピボットするのが理にかなっています。

### 完全な例: seccomp が `unshare` をブロックしていただけだった場合

多くのターゲットでは、seccomp を外すと実際に namespace 作成やマウント系のシステムコールが突然動作し始めます。コンテナが `CAP_SYS_ADMIN` を持っている場合、次のようなシーケンスが可能になることがあります：
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
それ自体ではまだ host escape ではありませんが、seccomp が mount-related exploitation を防いでいた障壁であることを示しています。

### 完全な例: seccomp 無効化 + cgroup v1 `release_agent`

もし seccomp が無効化され、container が cgroup v1 階層を mount できる場合、cgroups セクションの `release_agent` technique が到達可能になります:
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
これは seccomp-only exploit ではありません。ポイントは、seccomp が unconfined になると、以前はブロックされていた syscall-heavy breakout chains が、そのままの記述どおりに動作し始める可能性があることです。

## チェック

これらのチェックの目的は、seccomp がそもそも有効かどうか、`no_new_privs` が併用されているかどうか、そしてランタイム設定で seccomp が明示的に無効化されていないかを確認することです。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- 非ゼロの `Seccomp` 値はフィルタリングが有効であることを示す。`0` は通常 seccomp 保護がないことを意味する。
- ランタイムのセキュリティオプションに `seccomp=unconfined` が含まれる場合、ワークロードは最も有用な syscall レベルの防御の一つを失っている。
- `NoNewPrivs` は seccomp 自体ではないが、両方が一緒に見られる場合、どちらも無い状態よりもより慎重なハードニング姿勢を示すことが多い。

コンテナが既に疑わしいマウント、broad capabilities、または共有されたホスト namespaces を持ち、かつ seccomp が unconfined である場合、その組み合わせは重大なエスカレーションのシグナルとして扱うべきである。コンテナが必ずしも簡単に突破されるわけではないが、攻撃者が利用できるカーネルのエントリポイントの数は急増している。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Dockerの組み込みデフォルト seccomp プロファイルを、上書きされない限り使用する | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | ランタイムのデフォルト seccomp プロファイルを適用する（上書きされない限り） | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Not guaranteed by default** | `securityContext.seccompProfile` が未設定の場合、kubelet が `--seccomp-default` を有効にしていない限りデフォルトは `Unconfined` となる。`RuntimeDefault` または `Localhost` は明示的に設定する必要がある | `securityContext.seccompProfile.type: Unconfined`, クラスタに `seccompDefault` がない場合に seccomp を未設定のままにする、`privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Kubernetes が `RuntimeDefault` を要求する時、または kubelet の seccomp デフォルト化が有効なときにランタイムプロファイルが使用される | Kubernetes 行と同様；直接の CRI/OCI 設定でも seccomp を完全に省略できる |

Kubernetes の挙動は運用者を最も驚かせることが多い。多くのクラスターでは、Pod が要求するか kubelet が `RuntimeDefault` にデフォルト化するよう設定されていない限り、seccomp は依然として設定されていない。
{{#include ../../../../banners/hacktricks-training.md}}
