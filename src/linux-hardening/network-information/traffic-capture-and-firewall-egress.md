# Traffic Capture、Firewall、Egress のトリアージ

{{#include ../../banners/hacktricks-training.md}}

[ローカルリスナーとUnixソケット](local-network-and-socket-triage.md)を特定したら、どのインターフェースがそれらのトラフィックを運ぶのか、またどのFirewallルールやプロキシルールが到達可能性に影響するのかを調べます。ループバック限定のサービスでも、別のホストからアクセスできない場合に機密性の高いHTTPヘッダーを運んでいる可能性があります。

## キャプチャ権限を確認し、インターフェースを選択する

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` は、現在のユーザーに sudo 権限がなくても、パケットキャプチャ機能を持っている場合があります。実行ファイルの実際のケイパビリティとグループ権限を確認してください。役立つ範囲で、インターフェース、キャプチャ時間、フィルターを最小限にしてください。キャプチャには認証情報や個人データが含まれる可能性があります。

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` は平文の TCP ストリームを再構成し、`tshark` はキャプチャをフィルタリングしてフィールドを抽出できます。TLS トラフィックの復号には、接続前にエンドポイントの鍵を用意するか、`SSLKEYLOGFILE` を設定した対応クライアントを使用する必要があります。[ローカルネットワークのトリアージページ](local-network-and-socket-triage.md#tls-key-logging)で、この手順を確認できます。暗号化されたキャプチャを、読める平文として扱わないでください。

保存されたインシデント関連アーティファクトによって、この評価が変わることがあります。[Linux の core dump はプロセスメモリのイメージです](https://man7.org/linux/man-pages/man5/core.5.html)。その中にセッションキーが残っている可能性があります。読み取り可能な dump とパケットキャプチャが同一のプロセスおよびセッションから取得された場合、アナリストがそのトラフィックを復号できることがあります。まずアーティファクトのパスと権限を確認し、その後、プロセスの識別情報、キャプチャ時刻、プロトコル、鍵の形式を個別に検証してください。復号したトラフィックや復元したアーカイブは情報漏えいの手掛かりであり、別のアカウントがアクセスされた証拠ではありません。SSH 鍵の一部が見つかった場合も、その鍵を再構成し、対応する公開鍵と照合したうえで、そのアカウントの SSH ポリシーに受け入れられる必要があります。幅広い列挙結果に、core の内容やキャプチャのペイロードを出力しないでください。

## ファイアウォール層を特定する

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` と `iptables` は、UFW や firewalld などのディストリビューション提供ラッパーを介して利用できる場合があります。有効なルールとラッパーに保存された設定を確認してください。一方の形式で表示されるルールが、別のツールによって生成されていることがあります。サービスが特定のルールによってブロックされていると判断する前に、インターフェース、方向、送信元、宛先、プロトコル、ポート、接続状態を確認してください。詳しい例は[ nftables ルールの確認](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes)を参照してください。

## egress とプロキシの動作をテストする

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS の失敗と、TCP、TLS、または proxy の失敗を切り分けます。評価に関係する宛先とプロトコルを指定してテストしてください。ICMP で到達できても、TCP または UDP が許可されているとは限りません。proxy が設定されている場合は、意図した proxy 経由のリクエストと、該当する `no_proxy` ルールを適用した同じ宛先へのリクエストを比較します。ローカルポートフォワードによって loopback サービスを別の場所から利用できる場合もあるため、ファイアウォールの状況と実際に確認された公開範囲が一致しない場合は、アクティブなリスナーと SSH トンネルを確認してください。
{{#include ../../banners/hacktricks-training.md}}
