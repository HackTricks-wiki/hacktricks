# Linuxの基本

{{#include ../../banners/hacktricks-training.md}}

Linuxホストの評価はここから始めます。各ページでは、幅広い権限昇格のワークフロー、実用的なコマンド、環境変数、ホスト上で実行できるものに影響する一般的な制限について説明します。

- [Linux privilege escalation](linux-privilege-escalation/README.md)では、列挙とローカルでの権限昇格につながる可能性のある経路を解説します。短いタスクリストが必要な場合は、[権限昇格チェックリスト](../main-system-information/linux-privilege-escalation-checklist.md)を使用してください。
- [シェルの起動、エイリアス、履歴](shell-startup-aliases-and-history.md)では、コマンドの解決、起動ファイルの実行、履歴から得られる手がかりについて説明します。
- [Linuxの便利なコマンド](useful-linux-commands.md)には、ファイル、プロセス、サービス、環境を調査するためのコマンドをまとめています。
- [Linuxの環境変数](linux-environment-variables.md)では、環境変数が実行に与える影響と、機密情報が含まれる可能性のある場所について説明します。
- [Linuxの制限を回避する](bypass-linux-restrictions/README.md)では、ファイルシステムの保護、`noexec`、distrolessシステムなど、制限されたシェルや実行環境を扱います。

## ネイティブバイナリのexploit

評価の過程で脆弱なLinux実行ファイルが見つかった場合は、Binary Exploitationの関連資料を参照してください。

- [ELF形式とローダーの挙動](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)と[バイナリの保護機構と回避方法](../../binary-exploitation/common-binary-protections-and-bypasses/README.md)では、実行ファイルのレイアウトと緩和策について説明します。
- [スタックexploit](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md)と[ROP](../../binary-exploitation/rop-return-oriented-programing/README.md)では、制御フロー攻撃を扱います。
- [Libcヒープexploit](../../binary-exploitation/libc-heap/README.md)と[フォーマット文字列](../../binary-exploitation/format-strings/README.md)では、その他の一般的なメモリ破壊の経路を扱います。

カーネル固有の事例研究は、[Kernel/LPE/CVE資料](../main-system-information/kernel-lpe-cves/README.md)から参照できます。
{{#include ../../banners/hacktricks-training.md}}
