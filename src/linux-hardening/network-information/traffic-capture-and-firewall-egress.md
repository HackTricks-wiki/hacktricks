# トラフィックキャプチャ、ファイアウォール、エグレスのトリアージ

{{#include ../../banners/hacktricks-training.md}}

[ローカルリスナーと Unix ソケット](local-network-and-socket-triage.md)を特定したら、どのインターフェースがそれらのトラフィックを運び、どのファイアウォールやプロキシのルールが到達可能性に影響するかを調べます。ループバックのみで動作するサービスでも、別のホストから到達できない一方で、機密性の高い HTTP ヘッダーを扱っている場合があります。

## キャプチャ権限を確認し、インターフェースを選ぶ

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap`は、現在のユーザーにsudo権限がなくてもパケットキャプチャ機能を持っている場合があります。実行ファイルの実際のcapabilitiesとグループ権限を確認してください。必要最小限のインターフェース、時間、フィルターでキャプチャしてください。キャプチャには認証情報や個人データが含まれることがあります。

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` は平文の TCP ストリームを再構築し、`tshark` はキャプチャからフィルタリングしてフィールドを抽出できます。TLS トラフィックの復号には、エンドポイントの鍵、または接続前に `SSLKEYLOGFILE` を設定した対応クライアントが必要です。[ローカルネットワークのトリアージページ](local-network-and-socket-triage.md#tls-key-logging)で、その手順を確認できます。暗号化されたキャプチャを、読み取り可能な平文として扱わないでください。

保存されたインシデントのアーティファクトによって、この評価が変わることがあります。[Linux の core dump はプロセスメモリのイメージです](https://man7.org/linux/man-pages/man5/core.5.html)。セッションキーが保持されている可能性があり、読み取り可能な dump とパケットキャプチャが同じプロセスおよびセッションから取得されていれば、アナリストがそのトラフィックを復号できる場合があります。まずアーティファクトのパスと権限を確認し、次にプロセスの識別情報、キャプチャ時刻、プロトコル、鍵の形式をそれぞれ検証してください。復号したトラフィックや復元したアーカイブは情報漏えいの手掛かりであり、別のアカウントへのアクセスを証明するものではありません。部分的な SSH 鍵の情報があっても、再構成し、対応する公開鍵と照合したうえで、そのアカウントの SSH ポリシーに受け入れられる必要があります。幅広い列挙結果に core の内容やキャプチャのペイロードを出力しないでください。

## Firewall のレイヤーを特定する

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` と `iptables` は、UFW や firewalld などのディストリビューションのラッパー経由で公開されている場合があります。有効なルールとラッパーの永続化された設定を確認してください。一方の表示にあるルールが、別のツールによって生成されていることがあります。サービスが特定のルールによってブロックされていると判断する前に、インターフェース、方向、送信元、宛先、プロトコル、ポート、接続状態を確認してください。具体例は [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) を参照してください。

## 出方向通信とプロキシの動作をテストする

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS の失敗を、TCP、TLS、または proxy の失敗と区別します。評価対象に関連する宛先とプロトコルを指定してテストしてください。ICMP で到達できても、TCP や UDP が許可されているとは限りません。proxy が設定されている場合は、想定される proxy 経由のリクエストと、適用される `no_proxy` ルールの下で同じ宛先に送るリクエストを比較します。ローカルのポートフォワードによって loopback サービスが別の場所から利用可能になることもあるため、ファイアウォールの状態と実際に観測された公開状況が食い違う場合は、稼働中のリスナーと SSH トンネルを確認してください。
{{#include ../../banners/hacktricks-training.md}}
