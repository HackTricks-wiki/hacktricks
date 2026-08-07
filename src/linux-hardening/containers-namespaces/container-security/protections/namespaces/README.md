# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespacesは、containerが実際にはhostのprocess treeにすぎないにもかかわらず、「独自のmachine」であるかのように感じさせるkernelの機能です。Namespacesは新しいkernelを作成するものでも、すべてをvirtualizeするものでもありません。しかしkernelに、選択したresourceについて異なるprocess groupへ異なるviewを提供させることができます。これがcontainerのillusionの核心です。workloadからは、filesystem、process table、network stack、hostname、IPC resource、user/group identity modelがlocalに存在するように見えますが、基盤となるsystemは共有されています。

これが、containerの仕組みを学ぶ際に、Namespacesが多くの人にとって最初に出会うconceptである理由です。同時に、Namespacesは最も誤解されやすいconceptの1つでもあります。読者はしばしば、「Namespacesがある」ことを「安全にisolateされている」ことと同じだと考えてしまいます。実際には、namespaceは、それが設計された特定のresource classだけをisolateします。processがprivateなPID namespaceを持っていても、writableなhost bind mountを持っていれば危険です。privateなnetwork namespaceを持っていても、`CAP_SYS_ADMIN`を保持し、seccompなしで実行されていれば危険です。Namespacesは基盤となる要素ですが、最終的なboundaryにおける1つのlayerにすぎません。

## Namespace Types

Linux containerは通常、複数のnamespace typeを同時に利用します。**mount namespace**はprocessに個別のmount tableを提供し、制御されたfilesystem viewを実現します。**PID namespace**はprocessの可視性と番号付けを変更し、workloadからは独自のprocess treeが見えるようにします。**network namespace**はinterface、route、socket、firewall stateをisolateします。**IPC namespace**はSysV IPCとPOSIX message queueをisolateします。**UTS namespace**はhostnameとNIS domain nameをisolateします。**user namespace**はuser IDとgroup IDをremapし、container内のrootが必ずしもhost上のrootを意味しないようにします。**cgroup namespace**は可視化されるcgroup hierarchyをvirtualizeし、**time namespace**は新しいkernelで選択されたclockをvirtualizeします。

これらのnamespaceは、それぞれ異なる問題を解決します。そのため、実際のcontainer security analysisでは、**どのnamespaceがisolateされているか**、そして**どのnamespaceが意図的にhostと共有されているか**を確認することが重要になります。

## Host Namespace Sharing

多くのcontainer breakoutは、kernel vulnerabilityから始まるわけではありません。operatorが意図的にisolation modelを弱めることから始まります。`--pid=host`、`--network=host`、`--userns=host`の例は、ここではhost namespace sharingの具体例として使用している**Docker/Podman-style CLI flags**です。他のruntimeでは、同じ考え方を異なる方法で表現します。Kubernetesでは、通常、`hostPID: true`、`hostNetwork: true`、`hostIPC: true`などのPod設定が相当します。containerdやCRI-Oなどのlower-level runtime stackでは、同じ動作が、同じ名前のuser-facing flagではなく、生成されたOCI runtime configurationを通じて実現されることがよくあります。これらすべての場合で結果は似ています。workloadは、defaultのisolated namespace viewを受け取らなくなります。

このため、namespace reviewは「processが何らかのnamespace内にある」ことの確認だけで終わらせてはいけません。重要なのは、そのnamespaceがcontainer専用なのか、sibling containerと共有されているのか、それともhostに直接joinされているのかという点です。Kubernetesでは、同じ考え方が`hostPID`、`hostNetwork`、`hostIPC`などのflagで表されます。platformによって名前は変わりますが、risk patternは同じです。host namespaceを共有すると、containerに残っているprivilegeと、到達可能なhost stateの意味が大きくなります。

## Inspection

最も簡単な概要は次のとおりです。
```bash
ls -l /proc/self/ns
```
各エントリは、inodeのような識別子を持つsymbolic linkです。2つのプロセスが同じnamespace識別子を指している場合、それらはその種類の同じnamespaceに属しています。そのため、`/proc`は現在のプロセスと、マシン上にある他の興味深いプロセスを比較するのに非常に便利な場所です。

次の簡単なコマンドで、調査を始めるには十分なことがよくあります。
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
そこからの次のステップは、container process と host または近隣の process を比較し、namespace が実際に private かどうかを判断することです。

### Host からの Namespace Instance の列挙

すでに host access があり、特定の type の異なる namespace がいくつ存在するかを把握したい場合、`/proc` を使うと簡単に一覧を確認できます。
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
特定の namespace identifier に属するプロセスを見つけるには、`readlink` から `ls -l` に切り替え、対象の namespace 番号を grep します：
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
これらのコマンドは、ホスト上で1つの隔離された workload、多数の隔離された workload、または共有 namespace インスタンスとプライベート namespace インスタンスが混在して実行されているかどうかを判断できるため便利です。

### Target Namespace への移行

呼び出し元に十分な権限がある場合、`nsenter` は別のプロセスの namespace に参加する標準的な方法です。
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
これらの形式をまとめて示しているのは、すべての assessment で全形式が必要だからではありません。namespace-specific post-exploitation では、all-namespaces 形式だけを覚えているよりも、正確な entry syntax を把握しているほうが、作業がはるかに容易になることが多いためです。

## Pages

以下のページでは、各 namespace について詳しく説明しています。

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

読み進める際は、2つの点を意識してください。第一に、各 namespace が分離するのは、1種類の view だけです。第二に、private namespace は、残りの privilege model によってその分離が意味のあるものとして維持される場合にのみ有用です。

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | デフォルトでは、新しい mount、PID、network、IPC、および UTS namespace を使用します。user namespace は利用可能ですが、標準的な rootful setup ではデフォルトで有効になっていません | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Podman | デフォルトで新しい namespace を使用します。rootless Podman は自動的に user namespace を使用します。cgroup namespace のデフォルトは cgroup の version に依存します | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Kubernetes | デフォルトでは、Pod は host の PID、network、IPC を共有しません。Pod の network は各コンテナ単位ではなく、Pod に対して private です。user namespace は、対応する cluster で `spec.hostUsers: false` を設定することにより opt-in できます | `hostPID: true`、`hostNetwork: true`、`hostIPC: true`、`spec.hostUsers: true` / user-namespace opt-in の省略、privileged workload の設定 |
| containerd / CRI-O under Kubernetes | 通常は Kubernetes の Pod デフォルトに従います | Kubernetes の行と同じです。直接指定する CRI/OCI spec では、host namespace への join も要求できます |

主な portability rule は単純です。host namespace sharing という**概念**は各 runtime に共通していますが、**syntax**は runtime 固有です。

{{#include ../../../../../banners/hacktricks-training.md}}
