# Kernel、LPE、およびCVE関連資料

{{#include ../../../banners/hacktricks-training.md}}

これらの事例では、それぞれ異なるローカル権限昇格プリミティブを取り上げます。各記事の手法を適用する前に、影響を受ける製品またはkernel、設定、および前提条件を確認してください。ホストのより広範な列挙には、[Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md)を使用してください。

Dirty Pipe（CVE-2022-0847）については、[原著の調査](https://dirtypipe.cm4all.com/)で、upstream stableの修正バージョンが5.10.102、5.15.25、5.16.11とされています。古い影響対象バージョンのkernelが見つかった場合、それは追加調査の手掛かりにすぎません。ディストリビューションのkernelでは、異なるリリース名で修正がバックポートされることがあり、page-cache writeプリミティブを使うには対象ファイルを読み取り可能である必要があります。SUID実行ファイルを上書きする方法は、set-IDによる権限遷移が有効なままであれば、権限昇格の経路の一つになります。一方、`/etc/passwd`を変更してから認証する方法も、ローカルのPAM stackに左右される場合があります。到達可能性を評価する前に、インストール済みのベンダーkernelパッケージ、再起動後に実行中のkernel、対象ファイルの権限、mountの`nosuid`、および`no_new_privs`を確認してください。受動的な列挙中に書き込みプローブを実行しないでください。[Ubuntuのリリース別ステータス](https://ubuntu.com/security/CVE-2022-0847)を参照してください。

- [VMware Tools service discovery、CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：信頼できないプロセスパスの探索による特権実行。
- [AF_ALG spliceによるpage-cache上書き、CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：kernelのpage-cacheを上書きする経路。
- [POSIX CPU timersのTOCTOU raceとexploit、CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit)：task終了時のtimer満了と削除、およびIRQ経路の前提条件とexploitの調査。
- [Linux ptraceの終了時raceと`pidfd_getfd`によるfile descriptor窃取](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：プロセス終了時のraceをまたいだdescriptorアクセス。

## 関連するbinary exploitationの事例

Binary Exploitationセクションでは、これらのLinux kernelの対象に対するexploitプリミティブ、メモリレイアウト、および緩和策の回避について、さらに詳しく解説しています。

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：socketのバグをkernelのreadおよびwriteプリミティブへ発展させた事例。
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md)：skcipher writerのraceをkernelへのwriteへ発展させた事例。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：pointer-writeプリミティブをpipe bufferとworkqueueを通じて拡張した事例。
- [ksmbd streams out-of-bounds write、CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：kernel heapのexploitと緩和策の回避。
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：arm64 kernelのexploitに向けたアドレスの特定。
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：kernelメモリアクセスにつながるAndroid GPUの経路。
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：kernelへのwriteに利用されたAndroid acceleratorのバグ。
{{#include ../../../banners/hacktricks-training.md}}
