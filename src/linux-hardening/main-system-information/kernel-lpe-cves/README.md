# Kernel、LPE、CVE に関する資料

{{#include ../../../banners/hacktricks-training.md}}

これらのケーススタディでは、異なるローカル権限昇格プリミティブを取り上げます。手法を適用する前に、各記事で対象となる製品または kernel、設定、前提条件を確認してください。より広範なホスト列挙には、[Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md)を使用してください。

Dirty Pipe（CVE-2022-0847）については、[original research](https://dirtypipe.cm4all.com/)に、upstream stable での修正バージョンとして 5.10.102、5.15.25、5.16.11 が記載されています。古い影響対象バージョンの kernel は確認の手がかりにすぎません。ディストリビューションの kernel は異なるリリース名で修正をバックポートしている場合があり、page-cache write プリミティブを使用するには対象ファイルを読み取り可能である必要があります。set-ID の遷移が有効なままであれば、読み取り可能な SUID 実行ファイルの上書きが権限取得につながる可能性があります。また、`/etc/passwd` を変更してから認証する方法は、ローカルの PAM stack に依存する場合があります。到達可能性を評価する前に、インストール済みのベンダー kernel package、再起動後に実行される kernel、対象の権限、mount の `nosuid`、`no_new_privs` を確認してください。受動的な列挙中に write probe を実行しないでください。[Ubuntu's release-specific status](https://ubuntu.com/security/CVE-2022-0847)を参照してください。

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：信頼できない process-path discovery を介した特権実行。
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：kernel page-cache を上書きする経路。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md)：timer 処理における race。
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：process の終了 race 中における descriptor アクセス。

## 関連する binary exploitation のケーススタディ

Binary Exploitation セクションでは、これらの Linux kernel を対象とする exploit primitive、memory layout、mitigation bypasses をさらに詳しく取り上げます。

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：socket の bug を kernel の read および write primitive に発展させた例。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：pipe buffer と workqueue を介して拡張された pointer-write primitive。
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：kernel heap exploitation と mitigation bypasses。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md)：上記で要約した timer race を binary exploitation の観点から解説。
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：arm64 kernel exploitation におけるアドレスの特定。
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：kernel memory access に至る Android GPU の経路。
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：kernel write に利用された Android accelerator の bug。
{{#include ../../../banners/hacktricks-training.md}}
