# 興味深いファイルと権限

{{#include ../../banners/hacktricks-training.md}}

ファイルの所有権、書き込みアクセス、マウントオプション、実行権限によって、ローカルユーザーが実質的にアクセスできる範囲が変わることがあります。まず対象のファイルまたは実行経路を特定し、該当するページを参照してください。

- [SUID、SGID、ACL、機密ファイル](suid-sgid-and-acl-triage.md)では、実行権限と隠れたアクセス許可を調査するための基本的な手順を紹介しています。
- [任意のファイル書き込みによるroot権限取得](write-to-root.md)では、特権パスへの書き込みを権限昇格につなげる方法を説明しています。
- [Linux capabilities](linux-capabilities.md)では、プロセス単位およびファイル単位のcapabilitiesについて説明しています。
- [SUID共有ライブラリとlinkerの悪用](suid-shared-library-and-linker-abuse.md)では、特権バイナリにおける動的読み込みの悪用について説明しています。
- [`ld.so`による権限昇格の例](ld.so.conf-example.md)では、linker設定に関する事例を解説しています。
- [NFSの`no_root_squash`および`no_all_squash`の設定ミス](nfs-no_root_squash-misconfiguration-pe.md)では、リモートファイルシステムにおけるIDマッピングについて説明しています。
- [ワイルドカードによる引数展開のトリック](wildcards-spare-tricks.md)では、特権コマンドにおける引数展開について説明しています。
- [SELinux](selinux.md)では、ポリシーの適用と関連する調査手順について説明しています。
{{#include ../../banners/hacktricks-training.md}}
