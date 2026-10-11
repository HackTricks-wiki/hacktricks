# Linux の基礎

{{#include ../../banners/hacktricks-training.md}}

ここは Linux ホストの評価を始めるためのページです。各ページでは、幅広い権限昇格のワークフロー、実用的なコマンド、環境変数、ホスト上で実行できるものに影響する一般的な制限を扱います。

- [Linux privilege escalation](linux-privilege-escalation/README.md)では、列挙と、ローカルで権限昇格できる可能性のある経路を順を追って説明します。短いタスクリストが必要な場合は、[権限昇格チェックリスト](../main-system-information/linux-privilege-escalation-checklist.md)を使用してください。
- [Shell startup, aliases, and history](shell-startup-aliases-and-history.md)では、コマンドの解決、起動ファイルの実行、履歴から得られる手がかりについて説明します。
- [Useful Linux commands](useful-linux-commands.md)には、ファイル、プロセス、サービス、環境を調査するためのコマンドをまとめています。
- [Linux environment variables](linux-environment-variables.md)では、環境変数が実行にどう影響するか、機密情報がどこに現れる可能性があるかを説明します。
- [Bypass Linux restrictions](bypass-linux-restrictions/README.md)では、制限付きシェルや実行環境を取り上げ、ファイルシステムの保護、`noexec`、distroless システムなどについて説明します。

## ネイティブバイナリの悪用

評価の結果、脆弱な Linux 実行ファイルが見つかった場合は、Binary Exploitation の関連資料を参照してください。

- [ELF format and loader behavior](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)と[binary protections and bypasses](../../binary-exploitation/common-binary-protections-and-bypasses/README.md)では、実行ファイルのレイアウトと緩和策について説明します。
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md)と[ROP](../../binary-exploitation/rop-return-oriented-programing/README.md)では、制御フロー攻撃を扱います。
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md)と[format strings](../../binary-exploitation/format-strings/README.md)では、その他の一般的なメモリ破壊経路を扱います。

カーネル固有のケーススタディへのリンクは、[Kernel/LPE/CVE material](../main-system-information/kernel-lpe-cves/README.md)にあります。
{{#include ../../banners/hacktricks-training.md}}
