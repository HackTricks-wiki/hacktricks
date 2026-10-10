# 主要なシステム情報

{{#include ../../banners/hacktricks-training.md}}

ローカル権限昇格の手法を選ぶ前に、ホストのカーネル、ファイルシステム、特権ヘルパー、利用可能な脱出経路を調査してください。[権限昇格チェックリスト](linux-privilege-escalation-checklist.md)では、簡潔な作業手順を示しています。

- [カーネルの脆弱性評価と実行時の露出](kernel-vulnerability-assessment.md)では、ビルドの適用可能性、到達可能性、有効な緩和策を確認します。
- [カーネルモジュールとmodprobeの悪用](kernel-modules-and-modprobe.md)では、モジュールの読み込みとヘルパーパスの露出について説明します。
- [Sudoコマンドの悪用](sudo-command-abuse.md)では、委任されたコマンドが権限境界を越える方法を調査します。
- [シンボリックリンク、ハードリンク、ファイルディスクリプター](filesystem-links-and-file-descriptors.md)では、パスのリダイレクトや、継承されたファイルまたは削除後も開かれているファイルについて説明します。
- [ファイルシステム、inode、復旧](filesystem-inodes-and-recovery.md)では、調査に役立つファイルシステムの動作を説明します。
- [チェックリスト: Linuxの権限昇格](linux-privilege-escalation-checklist.md)では、ホストの確認項目と、詳しい資料へのリンクをまとめています。
- [jailからの脱出](escaping-from-limited-bash.md)では、制限付きシェルや制約された環境について説明します。
- [Kernel/LPE/CVE関連資料](kernel-lpe-cves/README.md)では、ローカル権限昇格と脆弱性に関する詳細な解説をまとめています。

{{#include ../../banners/hacktricks-training.md}}
