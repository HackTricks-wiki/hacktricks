# 興味深いファイルと権限

{{#include ../../banners/hacktricks-training.md}}

ファイルの所有権、書き込みアクセス、マウントオプション、実行権限によって、ローカルユーザーが実質的にアクセスできる範囲は変わります。まず対象のファイルまたは実行パスを特定し、該当するページを確認してください。

- [SUID、SGID、ACL、機密ファイル](suid-sgid-and-acl-triage.md)では、実行権限や隠れたアクセス許可を調査するための基本的な手順を紹介します。
- [rootへの任意のファイル書き込み](write-to-root.md)では、特権パスへの書き込みを権限昇格に利用する方法を説明します。
- [Linux capabilities](linux-capabilities.md)では、プロセス単位およびファイル単位のcapabilitiesについて説明します。
- [SUID共有ライブラリとリンカーの悪用](suid-shared-library-and-linker-abuse.md)では、特権バイナリでの動的ロードを利用する方法を扱います。
- [`ld.so`の権限昇格の例](ld.so.conf-example.md)では、リンカー設定に関するケースを解説します。
- [NFSの`no_root_squash`と`no_all_squash`の設定ミス](nfs-no_root_squash-misconfiguration-pe.md)では、リモートファイルシステムでのIDマッピングを扱います。
- [ワイルドカードの小技](wildcards-spare-tricks.md)では、特権コマンドにおける引数の展開を扱います。
- [SELinux](selinux.md)では、ポリシーによる強制と関連する調査手順を説明します。
{{#include ../../banners/hacktricks-training.md}}
