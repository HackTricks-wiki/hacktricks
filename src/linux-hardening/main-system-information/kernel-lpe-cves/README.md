# Kernel、LPE、および CVE の資料

{{#include ../../../banners/hacktricks-training.md}}

これらのケーススタディでは、それぞれ異なる local privilege escalation のプリミティブを取り上げます。手法を適用する前に、各記事で対象となる製品または kernel、設定、および前提条件を確認してください。より広範なホスト列挙には、[Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md) を使用してください。

Dirty Pipe（CVE-2022-0847）については、[original research](https://dirtypipe.cm4all.com/) に、upstream の安定版修正が 5.10.102、5.15.25、5.16.11 であると記載されています。古い影響対象範囲に含まれる kernel バージョンは、確認の手がかりにすぎません。ディストリビューションの kernel では、異なるリリース名で修正がバックポートされている場合があり、page-cache write プリミティブを使うには、対象ファイルが読み取り可能である必要があります。読み取り可能な SUID 実行ファイルを上書きする方法は、set-ID による権限切り替えが有効な場合に、権限昇格につながる可能性があります。また、`/etc/passwd` を変更してから認証する方法も、ローカルの PAM 構成に依存する場合があります。到達可能性を評価する前に、インストール済みのベンダー kernel パッケージ、再起動後に実行中の kernel、対象の権限、mount の `nosuid`、および `no_new_privs` を確認してください。受動的な列挙中に write probe を実行しないでください。[Ubuntu のリリース別ステータス](https://ubuntu.com/security/CVE-2022-0847)を参照してください。

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): 信頼できない process-path discovery を介した特権実行。
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel の page-cache overwrite 経路。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): timer 処理における race。
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): process の終了 race をまたいだ descriptor へのアクセス。

## 関連するバイナリ exploitation のケーススタディ

Binary Exploitation セクションでは、これらの Linux kernel ターゲットに関する exploit プリミティブ、メモリレイアウト、および緩和策の回避について、さらに詳しく解説しています。

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): socket のバグを、kernel の read および write プリミティブへと発展させたもの。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pipe buffer と workqueue を介して拡張された pointer-write プリミティブ。
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation と緩和策の回避。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): 上記で要約した timer race を、バイナリ exploitation の観点から解説。
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel exploitation のためのアドレス探索。
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): kernel メモリへのアクセスにつながる Android GPU の経路。
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel write に利用される Android accelerator のバグ。
{{#include ../../../banners/hacktricks-training.md}}
