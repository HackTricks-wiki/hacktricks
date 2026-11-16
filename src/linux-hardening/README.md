# Linuxハードニング

{{#include ../banners/hacktricks-training.md}}

このセクションでは、Linuxホストを調査し、権限の境界を理解し、ローカルアクセスを制限する制御を確認します。一般的な評価を行うには、まず[Linuxの基礎](linux-basics/README.md)と[権限昇格チェックリスト](main-system-information/linux-privilege-escalation-checklist.md)を確認し、その後、該当するトピックに進んでください。

- [Linuxの基礎](linux-basics/README.md): 権限昇格の方法論、便利なコマンド、環境変数、制限の回避方法。
- [システムの基本情報](main-system-information/README.md): カーネル、モジュール、sudo、ファイルシステムの挙動、jail、権限昇格チェックリスト。
- [ユーザー情報](user-information/README.md): LinuxのID、グループ、SSH agent forwarding、Active Directoryとの統合。
- [興味深いファイルと権限](interesting-files-permissions/README.md): 書き込み可能なパス、capabilities、SUIDの挙動、NFS、ワイルドカード展開、SELinux。
- [ネットワーク情報](network-information/README.md): ローカルサービス、ソケット、ネットワーク関連の悪用例。
- [ソフトウェア情報](software-information/README.md): 認証モジュールとアプリケーション固有の攻撃対象領域。
- [プロセス、crontab、systemd、D-Bus](processes-crontab-systemd-dbus/README.md): 定期実行とプロセス間通信。
- [コンテナと名前空間](containers-namespaces/README.md): ランタイム、分離境界、コンテナのハードニング。
- [AppArmorのポリシー制御ファイルの悪用](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): 特権ヘルパーが、ローカルユーザーによって開かれたAppArmor制御ファイルに書き込めるかどうかを評価します。
- [Post-exploitation](post-exploitation/README.md): 認証情報の探索、永続化、ホストレベルでの追加調査手法。

影響を受けるカーネルでは、非特権ユーザーがAppArmorのsecurityfsポリシー制御ファイルを開くことはできても、直接の書き込みは拒否される場合があります。特権ヘルパーがそのファイルを標準出力として引き継ぐと、書き込みによって読み込み済みのポリシーを変更できる可能性があります。これは、弱いコンテナプロファイルを見つけるだけの場合とは異なるローカル攻撃経路です。テストする前に、ベンダーのカーネルとヘルパーの修正状況を確認してください。<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Qualys CrackArmorの技術アドバイザリ](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu CrackArmor脆弱性ナレッジベース](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
