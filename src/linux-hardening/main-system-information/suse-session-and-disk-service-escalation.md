# SUSE セッションおよびディスクサービスの権限昇格を示す兆候

{{#include ../../banners/hacktricks-training.md}}

## PAM による SSH セッションの認可

CVE-2025-6018 は、SSH 認証スタックが `pam_env` を読み込んだ後に、セッションスタックが `pam_systemd` を読み込む SUSE 15 の PAM 設定に影響しました。`pam_env` がユーザーの `.pam_environment` を読み込む際、ユーザーは `XDG_SEAT` と `XDG_VTNR` の値を指定して、SSH セッションが物理的にアクティブであるかのように Polkit に認識させることができました。その結果、`allow_active=yes` のアクションがリモートユーザーに利用可能になる場合がありました。これはセッション認可を変更するものであり、それだけで root access が保証されるわけではありません。SUSE は `pam` のデフォルトのユーザー環境の動作と、`pam-config` が生成するモジュールの配置を修正しました。<sup>[[1]](#references)[[2]](#references)</sup>

有効な `/etc/pam.d/sshd` の include チェーン、`pam_env.so` と `pam_systemd.so` の順序、および明示的な `user_readenv=1` オプションの有無を確認してください。パッチ適用済みの `pam` パッケージではデフォルトの動作が変更されていますが、明示的なオプションがあれば、引き続きユーザー環境の読み込みが要求される場合があります。新しい `pam-config` パッケージがインストールされていても、ローカルで変更された、または古いままの PAM スタックが再生成された証明にはなりません。ベンダーのパッケージリリースと実際の設定をあわせて確認してください。<sup>[[1]](#references)[[2]](#references)</sup>

## アクティブユーザーを起点とするディスクサービス経路

CVE-2025-6019 は、`udisks2` 経由で使用される `libblockdev` の権限昇格経路でした。XFS の resize 中に、攻撃者が用意したファイルシステムが、想定される `nosuid` 制限なしで一時的にマウントされる可能性がありました。この経路には、利用可能な UDisks D-Bus サービス、XFS resize のサポート、呼び出し元が利用できる関連 Polkit アクション、および影響を受けるライブラリパッケージが必要です。CVE-2025-6018 はアクティブユーザーのセッションを得る方法の一つですが、すでにアクティブなユーザーであれば、それとは独立してディスクサービス経路を利用できます。<sup>[[3]](#references)</sup>

受動的な確認では、UDisks サービスのメタデータ、`org.freedesktop.udisks2.modify-device` ポリシー、`xfs_growfs`、およびインストールされている `libbd_fs2` パッケージを確認してください。SUSE は openSUSE Leap 15.6 向けに、`libbd_fs2` バージョン `2.26-150400.3.5.1` を修正済みとして記載しています。修正済みの正確なリリースは製品によって異なります。ポリシーやパッケージの存在は調査の手掛かりであり、呼び出し元がデバイスをマウントまたは resize できる証明にはなりません。列挙中にマウントを変更したり、D-Bus メソッドを呼び出したりしないでください。<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018 に関する勧告](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config セキュリティ更新](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019 に関する勧告](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
