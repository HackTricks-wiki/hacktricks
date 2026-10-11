# SUSE Session and Disk-Service Escalation Indicators

{{#include ../../banners/hacktricks-training.md}}

## PAMによるSSHセッションの認可

CVE-2025-6018は、SSH認証スタックが`pam_env`を読み込んだ後にセッションスタックが`pam_systemd`を読み込む、SUSE 15のPAM設定に影響しました。`pam_env`がユーザーの`.pam_environment`を読み込む際、ユーザーは`XDG_SEAT`と`XDG_VTNR`の値を指定して、SSHセッションが物理的にアクティブであるかのようにPolkitに認識させることができました。その結果、`allow_active=yes`のアクションをリモートユーザーが利用できる可能性がありました。これはセッション認可を変更するものであり、それ自体でrootアクセスが保証されるわけではありません。SUSEは、`pam`のデフォルトのユーザー環境動作と、`pam-config`が生成するモジュールの配置を修正しました。<sup>[[1]](#references)[[2]](#references)</sup>

有効な`/etc/pam.d/sshd`のincludeチェーン、`pam_env.so`と`pam_systemd.so`の順序、および明示的な`user_readenv=1`オプションの有無を確認してください。パッチ適用済みの`pam`パッケージではデフォルトの動作が変更されていますが、明示的なオプションを指定すれば、引き続きユーザー環境の読み込みを要求できます。`pam-config`パッケージが新しいだけでは、ローカルで変更されたPAMスタックや古いPAMスタックが再生成されたことの証明にはなりません。ベンダーのパッケージリリースと実際の設定を併せて確認してください。<sup>[[1]](#references)[[2]](#references)</sup>

## アクティブユーザーのディスクサービス経路

CVE-2025-6019は、`udisks2`経由で使用される`libblockdev`の権限昇格経路でした。XFSのサイズ変更中、攻撃者が用意したファイルシステムが、想定される`nosuid`制限なしで一時的にマウントされる可能性がありました。この経路の利用には、使用可能なUDisks D-Busサービス、XFSのサイズ変更サポート、呼び出し元が利用できる関連Polkitアクション、および影響を受けるライブラリパッケージが必要です。CVE-2025-6018はアクティブユーザーセッションを得る手段の一つですが、すでにアクティブなユーザーは、それとは独立してディスクサービス経路を利用できます。<sup>[[3]](#references)</sup>

受動的なレビューでは、UDisksサービスのメタデータ、`org.freedesktop.udisks2.modify-device`ポリシー、`xfs_growfs`、インストール済みの`libbd_fs2`パッケージを確認してください。SUSEは、openSUSE Leap 15.6向けに修正済みバージョンとして`libbd_fs2`の`2.26-150400.3.5.1`を挙げています。正確な修正版リリースは製品によって異なります。ポリシーやパッケージの存在は手掛かりにはなりますが、呼び出し元がデバイスをマウントまたはサイズ変更できる証明にはなりません。列挙中にマウントを変更したり、D-Busメソッドを呼び出したりすることは避けてください。<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018のアドバイザリ](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-configのセキュリティアップデート](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019のアドバイザリ](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
