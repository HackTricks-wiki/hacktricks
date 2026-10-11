# ネットワーク情報

{{#include ../../banners/hacktricks-training.md}}

ローカルのリスナー、Unixソケット、ネットワークに公開されたソフトウェアは、外部スキャンでは見えない経路を露呈することがあります。まず、ホストのリスニングサービスと各エンドポイントを所有するプロセスを確認します。

- [トラフィックキャプチャ、ファイアウォール、egressのトリアージ](traffic-capture-and-firewall-egress.md)では、パケットキャプチャ、フィルタリング、プロキシ、接続テストを扱います。
- [ローカルネットワークとソケットのトリアージ](local-network-and-socket-triage.md)では、ループバックサービス、Unixソケット、コンテナネットワークを扱います。
- [ソケット経由のコマンドインジェクション](socket-command-injection.md)では、公開されたローカルソケット経由で受け付けられるコマンドを扱います。
- [Cisco vManage](cisco-vmanage.md)では、製品固有のターゲットと関連する確認項目について説明します。
{{#include ../../banners/hacktricks-training.md}}
