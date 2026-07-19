# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces は、container が実際には host の process tree に過ぎないにもかかわらず、「それ自体の machine」のように感じられるようにする kernel の機能です。新しい kernel を作成したり、すべてを virtualize したりするわけではありませんが、kernel が選択された resource の異なる view を、異なる process group に提示できるようにします。これが container の illusion の中核です。workload からは、filesystem、process table、network stack、hostname、IPC resource、user/group identity model が local に見えますが、基盤となる system は共有されています。

これが、container の仕組みを学ぶ際に、ほとんどの人が最初に触れる概念が namespaces である理由です。同時に、読者が「namespaces がある」ことを「安全に isolation されている」ことと誤解しがちなため、最も誤解されている概念の 1 つでもあります。実際には、namespace は、それ用に設計された特定の resource class だけを isolation します。process が private PID namespace を持っていても、writable な host bind mount があれば危険です。private network namespace を持っていても、`CAP_SYS_ADMIN` を保持し、seccomp なしで動作していれば危険です。Namespaces は基盤となる要素ですが、最終的な boundary における 1 つの layer に過ぎません。

## Namespace Types

Linux containers は通常、複数の namespace types に同時に依存します。**mount namespace** は process に別個の mount table を提供し、それによって制御された filesystem view を与えます。**PID namespace** は process の可視性と番号付けを変更し、workload から自身の process tree が見えるようにします。**network namespace** は interface、route、socket、firewall state を isolation します。**IPC namespace** は SysV IPC と POSIX message queue を isolation します。**UTS namespace** は hostname と NIS domain name を isolation します。**user namespace** は user ID と group ID を remap するため、container 内の root が必ずしも host 上の root を意味するとは限りません。**cgroup namespace** は可視の cgroup hierarchy を virtualize し、**time namespace** は新しい kernel で一部の clock を virtualize します。

これらの namespace はそれぞれ異なる問題を解決します。そのため、実際の container security analysis では、**どの namespaces が isolation されているか**、そして **どの namespaces が意図的に host と共有されているか**を確認することが重要になります。

## Host Namespace Sharing

多くの container breakout は kernel vulnerability から始まるわけではありません。operator が意図的に isolation model を弱めることから始まります。`--pid=host`、`--network=host`、`--userns=host` は、ここで host namespace sharing の具体例として使用している **Docker/Podman-style CLI flags** です。その他の runtime では、同じ考え方が異なる方法で表現されます。Kubernetes では通常、`hostPID: true`、`hostNetwork: true`、`hostIPC: true` などの Pod settings として相当するものが現れます。containerd や CRI-O などの lower-level runtime stack では、同じ動作が、同名の user-facing flag ではなく、生成された OCI runtime configuration を通じて実現されることがよくあります。これらすべての場合において、結果はほぼ同じです。workload は default の isolated namespace view を受け取らなくなります。

このため、namespace review は「process が何らかの namespace 内にある」ことだけで終わらせてはいけません。重要なのは、その namespace が container 専用なのか、sibling containers と共有されているのか、それとも host に直接 join しているのかです。Kubernetes では、同じ考え方が `hostPID`、`hostNetwork`、`hostIPC` などの flags に現れます。platform によって名前は変わりますが、risk pattern は同じです。共有された host namespace によって、container に残された privilege と到達可能な host state の意味が大きくなります。

## Inspection

最も簡単な overview は次のとおりです。
```bash
ls -l /proc/self/ns
```
各エントリは、inodeに似た識別子を持つ symbolic link です。2つのプロセスが同じ namespace 識別子を指している場合、それらはその種類の同じ namespace に属しています。そのため、`/proc` は現在のプロセスと、マシン上にあるその他の興味深いプロセスを比較するのに非常に便利な場所です。

以下の簡単なコマンドで、調査を開始するには十分なことがよくあります。
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
そこからの次のステップは、container processをhostまたは近隣のprocessと比較し、namespaceが実際にprivateかどうかを判断することです。

### HostからNamespace Instanceを列挙する

すでにhost accessがあり、特定のtypeの異なるnamespaceがいくつ存在するかを把握したい場合、`/proc`を使うとすぐに一覧を確認できます。
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
特定の namespace identifier に属するプロセスを確認したい場合は、`readlink` の代わりに `ls -l` を使用し、対象の namespace number を grep します：
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
これらのコマンドは、ホストが1つの隔離された workload、多数の隔離された workload、または共有 namespace インスタンスとプライベート namespace インスタンスが混在した構成のいずれを実行しているかを判断できるため便利です。

### Target Namespace への移行

呼び出し元に十分な権限がある場合、`nsenter` は別のプロセスの namespace に参加する標準的な方法です：
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
これらの形式をまとめて列挙しているのは、すべての assessment でそのすべてが必要になるという意味ではありません。namespace 固有の post-exploitation は、all-namespaces 形式だけを覚えているのではなく、正確な entry syntax を把握していると、はるかに容易になることが多いという意味です。

## ページ

以下のページでは、それぞれの namespace について詳しく説明します。

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

これらを読む際は、2つの点を念頭に置いてください。第一に、各 namespace が分離するのは1種類の view だけです。第二に、private namespace は、残りの privilege model によってその分離が意味のあるものとして維持される場合にのみ有用です。

## Runtime のデフォルト

| Runtime / platform | デフォルトの namespace 状態 | 一般的な手動での弱体化 |
| --- | --- | --- |
| Docker Engine | デフォルトで新しい mount、PID、network、IPC、UTS namespace を作成します。user namespace は利用可能ですが、標準的な rootful setup ではデフォルトで有効化されていません | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Podman | デフォルトで新しい namespace を作成します。rootless Podman は自動的に user namespace を使用します。cgroup namespace のデフォルトは cgroup のバージョンによって異なります | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Kubernetes | デフォルトでは Pod は host の PID、network、IPC を共有しません。Pod の networking は各 container 単位ではなく Pod に対して private です。user namespace は、対応する cluster で `spec.hostUsers: false` を指定して opt-in できます | `hostPID: true`、`hostNetwork: true`、`hostIPC: true`、`spec.hostUsers: true` / user-namespace opt-in の省略、privileged workload の設定 |
| Kubernetes 上の containerd / CRI-O | 通常は Kubernetes の Pod デフォルトに従います | Kubernetes の行と同じです。直接の CRI/OCI spec では host namespace への join も要求できます |

主な portability rule は単純です。host namespace sharing という**概念**は各 runtime に共通していますが、その**syntax**は runtime 固有です。
{{#include ../../../../../banners/hacktricks-training.md}}
