# ネットワーク情報

{{#include ../../banners/hacktricks-training.md}}

ローカルで待ち受けているサービス、Unixソケット、ネットワークに公開されたソフトウェアは、外部スキャンでは見えない経路を露出させることがあります。まず、ホストの待ち受けサービスと、各エンドポイントを所有するプロセスを確認してください。

- [トラフィックキャプチャ、ファイアウォール、エグレスのトリアージ](traffic-capture-and-firewall-egress.md)では、パケットキャプチャ、フィルタリング、プロキシ、接続テストについて説明します。
- [ローカルネットワークとソケットのトリアージ](local-network-and-socket-triage.md)では、ループバックサービス、Unixソケット、コンテナネットワークについて説明します。
- [Socket command injection](socket-command-injection.md)では、公開されたローカルソケット経由で受け付けられるコマンドについて説明します。
- Cisco SD-WAN Managerアプライアンスへの足掛かりについては、[vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md)を参照してください。ConfD CLI、REST API、root所有のインポートパスは、一般的なソケットのトリアージとは別のものです。
{{#include ../../banners/hacktricks-training.md}}
