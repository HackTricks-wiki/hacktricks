# Linuxのハードニング

{{#include ../banners/hacktricks-training.md}}

このセクションでは、Linuxホストを調査し、権限の境界を把握して、ローカルアクセスを制限する制御を確認します。一般的な評価を行うには、まず[Linuxの基本](linux-basics/README.md)と[権限昇格チェックリスト](main-system-information/linux-privilege-escalation-checklist.md)を確認し、その後、関連するトピックに進んでください。

- [Linuxの基本](linux-basics/README.md): 権限昇格の手法、有用なコマンド、環境変数、制限のバイパス。
- [システムの主な情報](main-system-information/README.md): カーネル、モジュール、sudo、ファイルシステムの動作、jail、権限昇格チェックリスト。
- [ユーザー情報](user-information/README.md): LinuxのID、グループ、SSH agent forwarding、Active Directoryとの統合。
- [興味深いファイルと権限](interesting-files-permissions/README.md): 書き込み可能なパス、ケイパビリティ、SUIDの動作、NFS、ワイルドカード展開、SELinux。
- [ネットワーク情報](network-information/README.md): ローカルサービス、ソケット、ネットワーク関連のエクスプロイト例。
- [ソフトウェア情報](software-information/README.md): 認証モジュールとアプリケーション固有の攻撃対象領域。
- [プロセス、crontab、systemd、D-Bus](processes-crontab-systemd-dbus/README.md): スケジュール実行とプロセス間通信。
- [コンテナとnamespace](containers-namespaces/README.md): ランタイム、分離の境界、コンテナのハードニング。
- [Post-exploitation](post-exploitation/README.md): 認証情報の発見、永続化、ホストレベルでの追加調査手法。
{{#include ../banners/hacktricks-training.md}}
