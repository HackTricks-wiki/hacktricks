# Kernel、LPE、CVE に関する資料

{{#include ../../../banners/hacktricks-training.md}}

これらのケーススタディでは、それぞれ異なるローカル権限昇格プリミティブを取り上げます。手法を適用する前に、各記事で対象となる製品または kernel、設定、前提条件を確認してください。より広範なホスト列挙には、[Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md)を使用してください。

Dirty Pipe（CVE-2022-0847）については、[original research](https://dirtypipe.cm4all.com/)で、upstream stable の修正バージョンが 5.10.102、5.15.25、5.16.11 とされています。影響を受ける古いバージョン範囲の kernel は、調査の手がかりにすぎません。ディストリビューションの kernel では、異なるリリース名のまま修正が backport されている場合があります。また、page-cache write プリミティブを使うには、対象ファイルが読み取り可能である必要があります。読み取り可能な SUID 実行ファイルを上書きする方法は、set-ID による権限変更が有効な場合に、権限昇格につながる可能性があります。`/etc/passwd` を変更してから認証する方法も、ローカルの PAM 構成に左右されます。到達可能性を評価する前に、インストール済みのベンダー kernel パッケージ、再起動後に実行される kernel、対象ファイルの権限、マウント時の `nosuid`、`no_new_privs` を確認してください。パッシブな列挙中に書き込みプローブを実行しないでください。[Ubuntu's release-specific status](https://ubuntu.com/security/CVE-2022-0847)を参照してください。

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): 信頼されていないプロセスパスの探索を通じた、特権での実行。
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel の page-cache を上書きする経路。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): timer 処理における race。
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): プロセスの終了時に発生する race を利用した file descriptor へのアクセス。

## 関連するバイナリ悪用のケーススタディ

Binary Exploitation セクションでは、これらの Linux kernel ターゲットに関する exploit プリミティブ、メモリレイアウト、mitigation の回避について、より詳しく解説しています。

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): socket のバグを、kernel の read/write プリミティブへ発展させた事例。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pointer-write プリミティブを、pipe buffer と workqueue を通じて拡張した事例。
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap の悪用と mitigation の回避。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): 上記でも要約した timer race を、バイナリ悪用の観点から解説。
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel の悪用に向けたアドレスの特定。
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Android GPU を経由した kernel メモリへのアクセス。
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel への書き込みに利用された Android accelerator のバグ。
{{#include ../../../banners/hacktricks-training.md}}
