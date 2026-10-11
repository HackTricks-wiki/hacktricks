# Kernel、LPE、およびCVE関連資料

{{#include ../../../banners/hacktricks-training.md}}

これらのケーススタディでは、それぞれ異なるローカル権限昇格プリミティブを取り上げます。各記事で、適用前に影響を受ける製品またはカーネル、設定、前提条件を確認してください。より広範なホスト列挙には、[Linux権限昇格チェックリスト](../linux-privilege-escalation-checklist.md)を使用してください。

Dirty Pipe（CVE-2022-0847）については、[元の調査](https://dirtypipe.cm4all.com/)で、上流の安定版における修正バージョンとして5.10.102、5.15.25、5.16.11が示されています。影響を受ける旧バージョンの範囲に含まれるカーネルバージョンは、確認の手がかりにすぎません。ディストリビューションのカーネルは、異なるリリース名で修正をバックポートしている場合があり、page-cache書き込みプリミティブを使うには、対象ファイルが読み取り可能である必要があります。読み取り可能なSUID実行ファイルの上書きは、set-IDによる遷移が引き続き有効な場合に、権限昇格につながる可能性があります。また、`/etc/passwd`を変更してから認証する方法も、ローカルのPAMスタックに依存する場合があります。到達可能性を評価する前に、インストール済みのベンダー製カーネルパッケージ、再起動後に動作しているカーネル、対象ファイルの権限、マウントオプション`nosuid`、および`no_new_privs`を確認してください。受動的な列挙中に書き込みプローブを実行しないでください。[Ubuntuのリリース別ステータス](https://ubuntu.com/security/CVE-2022-0847)を参照してください。

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：信頼できないプロセスパス検出を介した特権実行。
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：カーネルのpage-cacheを上書きする経路。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md)：タイマー処理における競合。
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：プロセス終了時の競合を利用したファイルディスクリプタへのアクセス。

## 関連するバイナリ悪用のケーススタディ

Binary Exploitationセクションでは、これらのLinuxカーネルのターゲットに関するexploitプリミティブ、メモリレイアウト、緩和策の回避について、さらに詳しく解説しています。

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：ソケットのバグを、カーネルの読み取り・書き込みプリミティブへ発展させたもの。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：ポインタ書き込みプリミティブを、pipe bufferとworkqueueを通じて拡張したもの。
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：カーネルヒープの悪用と緩和策の回避。
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md)：上記でも要約したタイマー競合を、バイナリ悪用の観点から解説。
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：arm64カーネルの悪用に向けたアドレスの特定。
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：カーネルメモリアクセスにつながるAndroid GPUの経路。
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：カーネルへの書き込みに利用されたAndroidアクセラレータのバグ。
{{#include ../../../banners/hacktricks-training.md}}
