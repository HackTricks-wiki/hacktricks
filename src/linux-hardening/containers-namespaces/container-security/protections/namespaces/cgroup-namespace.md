# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

cgroup namespace は cgroups を置き換えるものではなく、それ自体がリソース制限を適用するわけでもありません。代わりに、プロセスから **cgroup hierarchy がどのように見えるか** を変更します。つまり、表示される cgroup path 情報を仮想化し、workload からはホスト全体の hierarchy ではなく、container にスコープされた view が見えるようにします。

これは主に visibility と情報削減のための機能です。環境を自己完結しているように見せ、ホストの cgroup layout に関する情報の露出を減らすのに役立ちます。控えめな機能に思えるかもしれませんが、ホストの構造を不必要に把握できると reconnaissance に役立ち、環境に依存する exploit chain を簡略化できるため、依然として重要です。

## 動作

private cgroup namespace がない場合、プロセスからは、マシンの hierarchy のうち必要以上の範囲を露出する、ホスト基準の cgroup path が見えることがあります。private cgroup namespace を使用すると、`/proc/self/cgroup` や関連する情報が container 自身の view によりローカライズされます。これは、workload によりクリーンでホストの情報を露出しにくい環境を見せたい、modern runtime stack で特に役立ちます。

この仮想化は `/proc/<pid>/cgroup` だけでなく、`/proc/<pid>/mountinfo` にも影響します。別の cgroup-namespace perspective から別のプロセスを読み取ると、namespace root の外側にある path は先頭に `../` components が付いた状態で表示されます。これは、委譲された subtree より上位を見ていることを示す便利な手がかりです。labs と post-exploitation で役立つ重要な点として、新しく作成した cgroup namespace では、`mountinfo` が新しい root を正しく反映する前に、その namespace 内から **cgroupfs remount** が必要になることがよくあります。そうしないと、`/..` のような mount root が表示されることがあります。これは、namespace 自体はすでに変更されていても、継承された mount が依然として ancestor-rooted view を公開していることを意味します。

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
`mountinfo` で新しい cgroup-namespace の root をより明確に表示したい場合は、新しい namespace 内から cgroup filesystem を remount し、もう一度比較します。
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
また、実行時の動作を次と比較します：
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
この変更は、cgroup enforcement が存在するかどうかではなく、主にプロセスから見えるものに関するものです。

## Security Impact

cgroup namespace は、**visibility-hardening layer** として理解するのが最適です。これだけでは、container に writable cgroup mounts、広範な capabilities、または危険な cgroup v1 環境がある場合、breakout を阻止できません。しかし、host cgroup namespace が共有されていると、プロセスはシステムの構成についてより多くを把握でき、host-relative cgroup paths と他の観測結果を対応付けやすくなる可能性があります。

**cgroup v2** では、delegation rules がより厳格であるため、namespace はやや重要になります。hierarchy が `nsdelegate` 付きで mount されている場合、kernel は cgroup namespaces を delegation boundaries として扱います。つまり、ancestor control files は delegatee の到達範囲外に置かれることになり、namespace root での writes は `cgroup.procs`、`cgroup.threads`、`cgroup.subtree_control` など、delegation に安全な files に制限されます。これでも namespace 自体が escape primitive になるわけではありませんが、compromised workload が検査できる対象と、安全に sub-cgroups を作成できる場所が変わります。

したがって、この namespace が container breakout writeups の主役になることは通常ありませんが、host information leakage を最小化し、cgroup delegation を制約するという、より広い目標には貢献します。

## Abuse

直接的な abuse value は、主に reconnaissance です。host cgroup namespace が共有されている場合は、表示される paths を比較し、host に関する情報を明らかにする hierarchy details を探します。
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
書き込み可能な cgroup パスも公開されている場合は、その可視性を危険な legacy interface の検索と組み合わせます：
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 自体で即座に escape できることはほとんどありませんが、cgroup-based abuse primitives をテストする前に環境をマッピングしやすくすることがよくあります。

簡単な runtime の実態確認も、攻撃経路の優先順位付けに役立ちます。Docker は `--cgroupns=host|private` を公開し、Podman は `host`、`private`、`container:<id>`、`ns:<path>` をサポートしています。特に Podman では、デフォルトは通常 **cgroup v1 では `host`**、**cgroup v2 では `private`** です。そのため、完全な OCI config を調べる前でも、cgroup のバージョンを特定するだけで、どの namespace posture である可能性が高いかが分かります。

### Modern v2 Recon: Is This A Delegated Subtree?

現代のホストでは、興味深い問いは `release_agent` ではなく、現在のプロセスが、nested groups を作成できるだけの可視性または write access を持つ、委譲された **cgroup v2** subtree 内に存在しているかどうかであることがよくあります。
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
有用な解釈:

- `cgroup2fs` は unified v2 hierarchy 内にいることを意味するため、classic v1-only `release_agent` chains を最初に推測するのは避けるべきです。
- `cgroup.controllers` は親から利用可能な controllers を示し、現在の subtree が children に展開できる可能性を示します。
- `cgroup.subtree_control` は descendants に対して実際に有効化されている controllers を示します。
- `cgroup.events` は `populated=0/1` を公開します。subtree が empty になったかを監視するのに便利ですが、v1 `release_agent` のような host-code-execution primitive では**ありません**。

別の process namespace を直接 inspect できる十分な privilege がすでにある場合は、次のコマンドで view を比較します:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 完全な例: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace だけでは、通常 escape には不十分です。実際の権限昇格は、ホストを明らかにする cgroup path と、書き込み可能な cgroup v1 interface を組み合わせた場合に発生します：
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
これらのファイルに到達可能で書き込み可能な場合は、[cgroups.md](../cgroups.md) の完全な `release_agent` exploitation flow に直ちに pivot してください。影響として、container 内部からホスト上でコード実行が可能になります。

書き込み可能な cgroup interface がない場合、影響は通常 reconnaissance に限定されます。

## チェック

これらのコマンドの目的は、process が private cgroup namespace view を持っているか、または本来必要な範囲を超えて host hierarchy に関する情報を取得しているかを確認することです。
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
ここで興味深い点:

- namespace identifier が、対象とするホストプロセスと一致する場合、cgroup namespace が共有されている可能性があります。
- `/proc/self/cgroup` 内のホストを明らかにするパスや、`mountinfo` 内の ancestor-rooted entries は、直接 exploit できない場合でも有用な reconnaissance 情報になります。
- `cgroup2fs` が使用されている場合、古い v1 primitives がまだ存在すると仮定するのではなく、delegation、表示される controllers、書き込み可能な subtrees に注目してください。
- cgroup mounts も書き込み可能な場合、visibility の問題はさらに重要になります。

cgroup namespace は、主な escape 防止メカニズムではなく、visibility-hardening layer として扱うべきです。ホストの cgroup 構造を不必要に公開すると、攻撃者にとっての reconnaissance value が増加します。

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
