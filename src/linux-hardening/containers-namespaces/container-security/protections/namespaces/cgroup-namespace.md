# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

cgroup namespace は cgroup を置き換えるものではなく、それ自体で resource limit を適用するものでもありません。代わりに、cgroup hierarchy が process にどのように表示されるかを変更します。つまり、表示される cgroup path information を仮想化し、workload からは host 全体の hierarchy ではなく、container にスコープされた view が見えるようにします。

これは主に visibility と information reduction のための機能です。環境を自己完結しているように見せ、host の cgroup layout に関する情報の露出を減らすのに役立ちます。控えめな機能に思えるかもしれませんが、host の構造が不要に見えると reconnaissance に利用されたり、environment に依存する exploit chain が簡単になったりするため、依然として重要です。

## 動作

private cgroup namespace がない場合、process からは host-relative な cgroup path が見え、マシンの hierarchy のうち必要以上の範囲が露出することがあります。private cgroup namespace を使用すると、`/proc/self/cgroup` や関連する情報が container 固有の view により近いものになります。これは、workload に対して、より整理され、host の情報を露出しにくい環境を見せたい modern runtime stack で特に有用です。

この仮想化は `/proc/<pid>/cgroup` だけでなく、`/proc/<pid>/mountinfo` にも影響します。異なる cgroup-namespace perspective から別の process を読み取ると、namespace root の外側にある path は先頭に `../` component が付いた形で表示されます。これは、delegated subtree より上位を見ていることを示す便利な手がかりです。Lab や post-exploitation で重要な nuance として、新しく作成した cgroup namespace では、`mountinfo` に新しい root を正しく反映させる前に、通常、その namespace 内から **cgroupfs remount** を実行する必要があります。そうしないと、namespace 自体はすでに変更されているにもかかわらず、継承された mount が ancestor-rooted view を公開し続けているため、`/..` のような mount root が表示されることがあります。<sup>[[1]](#references)</sup>

## Lab

次のコマンドで cgroup namespace を確認できます。
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
`mountinfo` に新しい cgroup-namespace の root をより明確に表示させたい場合は、新しい namespace 内から cgroup filesystem を再マウントし、もう一度比較します：
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
そして、ランタイム動作を以下と比較する：
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
この変更は、cgroup enforcement が存在するかどうかではなく、主にプロセスから何が見えるかに関するものです。

## セキュリティへの影響

cgroup namespace は、**visibility-hardening layer** として理解するのが最適です。それ自体では、container に writable な cgroup mounts、広範な capabilities、または危険な cgroup v1 環境がある場合に breakout を阻止することはできません。しかし、host cgroup namespace が共有されていると、プロセスはシステムの構成についてより多くを把握でき、host-relative な cgroup paths を他の観察結果と対応付けやすくなる可能性があります。

**cgroup v2** では delegation rules がより厳格であるため、namespace の重要性がやや高まります。hierarchy が `nsdelegate` 付きで mount されている場合、kernel は cgroup namespaces を delegation boundaries として扱います。つまり、ancestor control files は delegatee の到達範囲外に留められることになり、namespace root での writes は `cgroup.procs`、`cgroup.threads`、`cgroup.subtree_control` などの delegation-safe files に制限されます。<sup>[[2]](#references)</sup> それでも namespace 自体が escape primitive になるわけではありませんが、compromised workload が検査できる対象と、安全に sub-cgroups を作成できる場所が変わります。

したがって、この namespace は container breakout writeups で通常主役になるものではありませんが、host information leak を最小化し、cgroup delegation を制約するという、より広い目的には貢献します。

## Abuse

直接的な abuse value は、主に reconnaissance です。host cgroup namespace が共有されている場合は、表示される paths を比較し、host を明らかにする hierarchy の詳細を探します。
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
書き込み可能な cgroup パスも公開されている場合は、その可視性を危険なレガシーインターフェースの検索と組み合わせます：
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 自体が即座に escape を実現することはほとんどありませんが、cgroup-based abuse primitives をテストする前に、環境をマッピングしやすくすることがよくあります。

簡単な runtime の現状確認も、attack path の優先順位付けに役立ちます。Docker は `--cgroupns=host|private` を公開し、Podman は `host`、`private`、`container:<id>`、`ns:<path>` をサポートしています。特に Podman では、デフォルトは通常 **cgroup v1 では `host`**、**cgroup v2 では `private`** です。そのため、完全な OCI config を調査する前でも、cgroup のバージョンを特定するだけで、どの namespace posture になっている可能性が高いかがわかります。

### Modern v2 Recon: これは委譲されたサブツリーか？

modern host では、関心の対象は `release_agent` ではなく、現在のプロセスが、nested group を作成するのに十分な可視性または書き込みアクセスを持つ、委譲された **cgroup v2** サブツリー内に存在するかどうかであることがよくあります。
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
有用な解釈:

- `cgroup2fs` は統合された v2 hierarchy 内にいることを意味するため、従来の v1 専用 `release_agent` chains を最初に推測するのは避けるべきです。
- `cgroup.controllers` は parent から利用可能な controllers を示し、現在の subtree が children に何を fan out できる可能性があるかを示します。
- `cgroup.subtree_control` は descendants に対して実際に enabled になっている controllers を示します。
- `cgroup.events` は `populated=0/1` を公開します。これは subtree が empty になったかどうかを監視するのに便利ですが、v1 の `release_agent` のような host-code-execution primitive では**ありません**。

別の process namespace を直接 inspect するのに十分な privilege がすでにある場合は、次のコマンドで views を比較します:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 完全な例: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace だけでは、通常 escape には不十分です。実際の権限昇格は、host を明らかにする cgroup パスと、書き込み可能な cgroup v1 interfaces を組み合わせた場合に発生します:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
それらのファイルに到達可能で、かつ書き込み可能な場合は、[cgroups.md](../cgroups.md) の完全な `release_agent` exploitation flow に直ちに pivot してください。影響として、container 内部から host code execution が可能になります。

書き込み可能な cgroup interfaces がない場合、影響は通常 reconnaissance に限定されます。

## Checks

これらのコマンドの目的は、process が private cgroup namespace view を持っているか、または本当に必要な範囲を超えて host hierarchy の情報を取得しているかを確認することです。
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
ここで興味深い点：

- namespace identifier が対象の host process と一致する場合、cgroup namespace が共有されている可能性があります。
- `/proc/self/cgroup` にある host を明らかにするパスや、`mountinfo` にある ancestor-rooted entries は、直接 exploit できない場合でも有用な reconnaissance 情報になります。
- `cgroup2fs` が使用されている場合、古い v1 primitives が依然として存在すると想定するのではなく、delegation、可視な controllers、書き込み可能な subtrees に注目します。
- cgroup mounts も書き込み可能な場合、visibility の問題はさらに重要になります。

cgroup namespace は、主要な escape 防止メカニズムではなく、visibility-hardening layer として扱うべきです。host の cgroup 構造を不必要に公開すると、attacker にとっての reconnaissance value が高まります。

## References

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
