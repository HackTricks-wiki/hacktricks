# メインシステム情報

{{#include ../../banners/hacktricks-training.md}}

ローカル権限昇格の手法を選ぶ前に、ホストのカーネル、ファイルシステム、特権ヘルパー、利用可能なエスケープ経路を調査します。[権限昇格チェックリスト](linux-privilege-escalation-checklist.md)には、簡潔な実行順序がまとめられています。

- [カーネルの脆弱性評価と実行時の露出](kernel-vulnerability-assessment.md)では、ビルドの適用可能性、到達可能性、有効な緩和策を確認します。
- [カーネルモジュールとmodprobeの悪用](kernel-modules-and-modprobe.md)では、モジュールの読み込みとヘルパーパスの露出を扱います。
- [Sudoコマンドの悪用](sudo-command-abuse.md)では、委譲されたコマンドが権限境界を越える方法を調べます。
- [シンボリックリンク、ハードリンク、ファイルディスクリプター](filesystem-links-and-file-descriptors.md)では、パスのリダイレクトと、継承されたファイルまたは削除済みだが開かれているファイルを扱います。
- [ファイルシステム、inode、復旧](filesystem-inodes-and-recovery.md)では、調査に役立つファイルシステムの挙動を説明します。
- [チェックリスト: Linuxの権限昇格](linux-privilege-escalation-checklist.md)には、ホストの確認項目と、詳細な資料へのリンクが記載されています。
- [jailからのエスケープ](escaping-from-limited-bash.md)では、制限付きシェルや制約された環境を扱います。
- [Kernel/LPE/CVE関連資料](kernel-lpe-cves/README.md)には、ローカル権限昇格と脆弱性に関する個別の解説をまとめています。
{{#include ../../banners/hacktricks-training.md}}
