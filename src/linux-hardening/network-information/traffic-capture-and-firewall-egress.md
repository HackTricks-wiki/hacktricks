# トラフィックキャプチャ、ファイアウォール、Egressのトリアージ

{{#include ../../banners/hacktricks-training.md}}

[ローカルリスナーとUnixソケット](local-network-and-socket-triage.md)を確認したら、どのインターフェースがそれらのトラフィックを運び、どのファイアウォールやプロキシのルールが到達可能性に影響しているかを調べます。ループバックのみで待ち受けるサービスでも、他のホストから到達できない場合に、機密性の高いHTTPヘッダーを扱っていることがあります。

## キャプチャ権限を確認し、インターフェースを選ぶ

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` は、現在のユーザーに sudo 権限がなくても、パケットキャプチャ機能を持っている場合があります。実行ファイルに実際に設定されている capabilities とグループ権限を確認してください。必要最小限のインターフェース、キャプチャ時間、フィルターを指定してください。キャプチャには認証情報や個人データが含まれる可能性があります。

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow`は平文のTCPストリームを再構成し、`tshark`はキャプチャをフィルタリングしてフィールドを抽出できます。TLSトラフィックの復号には、接続前にエンドポイントの鍵を用意するか、`SSLKEYLOGFILE`を設定した対応クライアントを使用する必要があります。[ローカルネットワークのトリアージページ](local-network-and-socket-triage.md#tls-key-logging)で、その手順を確認できます。暗号化されたキャプチャを、読み取り可能な平文として扱わないでください。

保存済みのインシデントアーティファクトによって、この評価が変わる場合があります。[Linux core dumpはプロセスメモリのイメージです](https://man7.org/linux/man-pages/man5/core.5.html)。その中にセッションキーが残っている可能性があります。読み取り可能なダンプとパケットキャプチャが同じプロセスとセッションから取得された場合、アナリストがそのトラフィックを復号できることがあります。まずアーティファクトのパスと権限を確認し、その後、プロセスの識別情報、キャプチャ時刻、プロトコル、鍵の形式をそれぞれ検証してください。復号したトラフィックや復元したアーカイブは情報開示の手がかりであり、別のアカウントへのアクセスを証明するものではありません。SSH鍵の一部しか得られなかった場合も、復元し、対応する公開鍵と照合したうえで、そのアカウントのSSHポリシーに認められる必要があります。広範な列挙結果にcore dumpの内容やキャプチャのペイロードを出力しないでください。

## ファイアウォールのレイヤーを特定する

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` と `iptables` は、UFW や firewalld などのディストリビューションのラッパーを通じて公開されている場合があります。有効なルールとラッパーに保存された設定を確認してください。一方の表示形式で確認できるルールが、別のツールによって生成されている場合があります。サービスが特定のルールによってブロックされていると判断する前に、インターフェース、方向、送信元、宛先、プロトコル、ポート、接続状態を確認してください。詳しい例は[ nftables のルールレビュー](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes)を参照してください。

## egress とプロキシの挙動をテストする

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS の失敗と、TCP、TLS、または proxy の失敗を切り分けます。評価に関連する宛先とプロトコルを指定してテストしてください。ICMP で到達可能でも、TCP や UDP が許可されているとは限りません。proxy が設定されている場合は、意図した proxy 経由のリクエストと、該当する `no_proxy` ルールを適用した同じ宛先へのリクエストを比較します。ローカルの port forward によって loopback サービスが別の場所から利用可能になることもあるため、firewall の状況と実際に観測された公開範囲が一致しない場合は、アクティブな listener と SSH tunnel を確認してください。
{{#include ../../banners/hacktricks-training.md}}
