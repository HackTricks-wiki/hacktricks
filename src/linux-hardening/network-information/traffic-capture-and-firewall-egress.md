# トラフィックキャプチャ、ファイアウォール、egressのトリアージ

{{#include ../../banners/hacktricks-training.md}}

[ローカルのリスナーとUnixソケット](local-network-and-socket-triage.md)を特定したら、どのインターフェースがそれらのトラフィックを運び、どのファイアウォールまたはプロキシのルールが到達可能性に影響するかを調べます。ループバックのみのサービスでも、別のホストから到達できない場合に機密性の高いHTTPヘッダーを運んでいる可能性があります。

## キャプチャ権限を確認し、インターフェースを選択する

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap`は、現在のユーザーにsudoアクセス権がなくても、パケットキャプチャ機能を持っている場合があります。実行ファイルの実際のケイパビリティとグループ権限を確認してください。役立つ範囲で、インターフェース、キャプチャ時間、フィルターを最小限にしてください。キャプチャには認証情報や個人データが含まれる可能性があります。

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` は平文の TCP ストリームを再構成し、`tshark` はキャプチャをフィルタリングしてフィールドを抽出できます。TLS トラフィックを復号するには、接続前にエンドポイントの鍵を用意するか、`SSLKEYLOGFILE` を設定した対応クライアントを使用する必要があります。[local network triage page](local-network-and-socket-triage.md#tls-key-logging) にその手順が示されています。暗号化されたキャプチャを、平文として読めるものと見なさないでください。

保存されたインシデントアーティファクトがあれば、この評価が変わる場合があります。[Linux のコアダンプはプロセスメモリのイメージです](https://man7.org/linux/man-pages/man5/core.5.html)。セッションキーが保持されている可能性があり、読み取り可能なダンプとパケットキャプチャが同じプロセスおよびセッションから取得されたものであれば、アナリストがそのトラフィックを復号できる場合があります。まずアーティファクトのパスと権限を調べ、その後、プロセスの識別情報、キャプチャ時刻、プロトコル、鍵の形式を個別に確認してください。復号したトラフィックや復元したアーカイブは、情報漏えいの手掛かりであり、別のアカウントへのアクセスを証明するものではありません。部分的な SSH 鍵の情報は再構成し、対応する公開鍵と照合したうえで、そのアカウントの SSH ポリシーによって受け入れられる必要があります。広範な列挙結果にコアダンプの内容やキャプチャのペイロードを出力しないでください。

## Firewall のレイヤーを特定する

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` と `iptables` は、UFW や firewalld などのディストリビューションのラッパー経由で公開されている場合があります。有効なルールとラッパーに保存された設定を確認してください。一方の表示にあるルールが、別のツールによって生成されていることがあります。特定のルールがサービスをブロックしていると判断する前に、インターフェース、方向、送信元、宛先、プロトコル、ポート、接続状態を確認してください。具体例は[ nftables ルールの確認](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes)を参照してください。

## egress と proxy の動作をテストする

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS の失敗と、TCP、TLS、またはプロキシの失敗を切り分けます。評価に関連する宛先とプロトコルを指定してテストしてください。ICMP で到達できても、TCP または UDP が許可されているとは限りません。プロキシが設定されている場合は、想定されるプロキシ経由のリクエストと、適用される `no_proxy` ルールに従って同じ宛先へ直接送信した場合を比較します。ローカルのポートフォワードによって loopback サービスが別の場所から利用可能になることもあるため、firewall の状態と実際に確認された公開状況が一致しない場合は、アクティブなリスナーと SSH トンネルを確認してください。
{{#include ../../banners/hacktricks-training.md}}
