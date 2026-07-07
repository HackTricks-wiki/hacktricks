# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace は cgroups を置き換えるものではなく、またそれ自体で resource limits を強制するものでもありません。代わりに、プロセスに対して **cgroup hierarchy がどう見えるか** を変えます。言い換えると、見える cgroup path 情報を仮想化し、ワークロードに full host hierarchy ではなく container スコープの view を見せます。

これは主に可視性と情報削減の機能です。environment を自己完結して見せ、host の cgroup layout に関する情報を少なくします。控えめに聞こえるかもしれませんが、それでも重要です。なぜなら、host structure への不要な可視性は reconnaissance に役立ち、environment-dependent exploit chains を単純化しうるからです。

## Operation

private cgroup namespace がない場合、プロセスは host-relative な cgroup paths を見てしまい、machine の hierarchy を本来より多く露出することがあります。private cgroup namespace では、`/proc/self/cgroup` と関連する観測結果は container 自身の view により局所化されます。これは、ワークロードによりクリーンで host を露出しにくい environment を見せたい modern runtime stacks で特に有用です。

virtualization は `/proc/<pid>/cgroup` だけでなく `/proc/<pid>/mountinfo` にも影響します。別の cgroup-namespace の視点から別の process を読むと、namespace root の外側にある path は先頭に `../` components を付けて表示されます。これは、自分の delegated subtree の上を見ていることを示す便利な手がかりです。labs や post-exploitation で役立つ nuance として、新しく作成された cgroup namespace は、`mountinfo` が新しい root をきれいに反映する前に、しばしばその namespace 内からの **cgroupfs remount** を必要とします。そうしないと、`/..` のような mount root がまだ見えることがあります。これは、namespace 自体はすでに変わっていても、継承された mount がなお ancestor-rooted view を露出していることを意味します。

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
`mountinfo` で新しい cgroup-namespace の root をより明確に表示したい場合は、新しい namespace の内側から cgroup filesystem を再マウントして、もう一度比較してください:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
そして、次と runtime behavior を比較してください:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
変更点は主に、cgroup enforcement が存在するかどうかではなく、プロセスが何を見られるかにあります。

## Security Impact

cgroup namespace は、**可視性を hardening する層**として理解するのが最適です。単体では、コンテナに writable な cgroup mount、広い capabilities、または危険な cgroup v1 環境がある場合の breakout を止めることはできません。しかし、host の cgroup namespace が共有されていると、プロセスはシステムがどう整理されているかについてより多くを知り、host-relative な cgroup path を他の観測結果と突き合わせやすくなる可能性があります。

**cgroup v2** では、delegation rules がより厳しいため、この namespace の重要性が少し増します。hierarchy が `nsdelegate` 付きで mount されている場合、kernel は cgroup namespaces を delegation boundary として扱います。つまり、ancestor の control files は delegatee の到達範囲外に置かれるべきであり、namespace root での write は `cgroup.procs`, `cgroup.threads`, `cgroup.subtree_control` のような delegation-safe な files に制限されます。これでも namespace 自体が escape primitive になるわけではありませんが、侵害された workload が何を inspect できるか、どこに安全に sub-cgroups を作れるかは変わります。

そのため、この namespace は通常 container breakout の writeup で主役になることはありませんが、host information leakage を最小化し、cgroup delegation を制約するというより広い目的には依然として貢献します。

## Abuse

即時の abuse value は主に reconnaissance です。host cgroup namespace が共有されている場合、見えている path を比較し、host を示唆する hierarchy の詳細を探してください：
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
書き込み可能な cgroup パスも公開されている場合は、その可視性を危険なレガシーインターフェースの検索と組み合わせてください:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace自体が即時のescapeをもたらすことはまれですが、cgroupベースのabuse primitivesを試す前に環境をマップしやすくすることがよくあります。

簡単なruntimeの現実確認も、attack pathの優先順位付けに役立ちます。Dockerは `--cgroupns=host|private` を公開しており、Podmanは `host`、`private`、`container:<id>`、`ns:<path>` をサポートしています。特にPodmanでは、デフォルトは通常 **cgroup v1では `host`**、**cgroup v2では `private`** なので、cgroupのバージョンを特定するだけで、完全なOCI configを確認する前でも、どちらのnamespace postureである可能性が高いかが分かります。

### Modern v2 Recon: Is This A Delegated Subtree?

modern hostでは、興味深い問いはしばしば `release_agent` ではなく、現在のprocessが、nested groupsを作成できるだけの可視性や書き込みアクセスを持つ delegated な **cgroup v2** subtree の中にいるかどうかです:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
役立つ解釈:

- `cgroup2fs` は unified v2 hierarchy にいることを意味するので、従来の v1-only な `release_agent` chain を最初の候補にすべきではありません。
- `cgroup.controllers` は parent から利用可能な controller を示し、したがって現在の subtree が children に対してどこまで fan out できる可能性があるかを示します。
- `cgroup.subtree_control` は、descendants に対して実際に有効化されている controller を示します。
- `cgroup.events` は `populated=0/1` を公開し、subtree が空になったかどうかを監視するのに便利ですが、v1 `release_agent` のような host-code-execution primitive では**ありません**。

すでに別の process namespace を直接 inspect するのに十分な privilege があるなら、次で views を比較してください:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 完全な例: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace だけでは、通常 escape には不十分です。実際の escalation は、ホストを示す cgroup path が writable な cgroup v1 interfaces と組み合わさったときに起こります:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
そのファイルに到達できて書き込み可能なら、[cgroups.md](../cgroups.md) の完全な `release_agent` exploit flow にすぐ pivot してください。影響は、container 内からの host code execution です。

書き込み可能な cgroup interface がなければ、影響は通常 reconnaissance に限定されます。

## Checks

これらのコマンドの目的は、process が private な cgroup namespace view を持っているのか、それとも本来必要以上に host hierarchy について学んでしまっているのかを確認することです。
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
ここで興味深いのは次の点です:

- namespace identifier が注目している host process と一致する場合、cgroup namespace は共有されている可能性があります。
- `/proc/self/cgroup` の host を示す path や、`mountinfo` の ancestor-rooted entries は、直接 exploit できなくても有用な reconnaissance になります。
- `cgroup2fs` が使われている場合は、古い v1 の primitives がまだ存在すると仮定するのではなく、delegation、表示される controllers、そして writable subtrees に注目してください。
- cgroup mounts も writable なら、visibility の問題はさらに重要になります。

cgroup namespace は、primary escape-prevention mechanism ではなく、visibility-hardening layer として扱うべきです。host の cgroup structure を不必要に公開すると、attacker に reconnaissance の価値を与えてしまいます。

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
