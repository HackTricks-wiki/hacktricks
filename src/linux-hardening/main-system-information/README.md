# メインシステム情報

{{#include ../../banners/hacktricks-training.md}}

ローカル権限昇格の手法を選ぶ前に、ホストのkernel、filesystem、特権ヘルパー、利用可能な脱出経路を確認します。[権限昇格チェックリスト](linux-privilege-escalation-checklist.md)には、簡潔な作業手順がまとめられています。

- [Kernelの脆弱性評価と実行時の露出](kernel-vulnerability-assessment.md)では、ビルドの適用可否、到達可能性、有効な緩和策を確認します。
- [Kernelモジュールとmodprobeの悪用](kernel-modules-and-modprobe.md)では、モジュールの読み込みとヘルパーパスの露出を扱います。
- [Sudoコマンドの悪用](sudo-command-abuse.md)では、委任されたコマンドが権限境界を越える方法を調べます。
- [Symlink、hardlink、file descriptor](filesystem-links-and-file-descriptors.md)では、パスのリダイレクトや、継承されたファイルまたは削除済みのオープンファイルを扱います。
- [Filesystem、inode、復旧](filesystem-inodes-and-recovery.md)では、調査に役立つfilesystemの動作を説明します。
- [チェックリスト: Linuxの権限昇格](linux-privilege-escalation-checklist.md)では、ホストの確認項目と、より詳細な資料へのリンクを掲載しています。
- [jailからの脱出](escaping-from-limited-bash.md)では、制限付きshellや制約された環境を扱います。
- [Kernel/LPE/CVE関連資料](kernel-lpe-cves/README.md)では、ローカル権限昇格と脆弱性に関する個別の解説をまとめています。
{{#include ../../banners/hacktricks-training.md}}
