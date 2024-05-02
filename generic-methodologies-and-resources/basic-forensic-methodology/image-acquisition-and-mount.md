# 画像取得とマウント

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を使って、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**私をフォロー**してください 🐦[@carlospolopm](https://twitter.com/hacktricks_live)**。**
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 取得

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTKイメージャ

[**ここからFTKイメージャをダウンロードできます**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1)。
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

[**ewf tools**](https://github.com/libyal/libewf)を使用してディスクイメージを生成できます。
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## マウント

### いくつかのタイプ

**Windows**では、Arsenal Image Mounterの無料版を使用して、[https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)で**フォレンジックイメージをマウント**することができます。

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

ボリュームをマウントするためのWindowsアプリケーションです。[こちら](https://arsenalrecon.com/downloads/)からダウンロードできます。

### エラー

* **`cannot mount /dev/loop0 read-only`** この場合、フラグ **`-o ro,norecovery`** を使用する必要があります。
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** この場合、ファイルシステムのオフセットがディスクイメージのものと異なるため、マウントに失敗しました。セクターサイズと開始セクターを見つける必要があります。
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
注意してください。セクターサイズは**512**で、開始位置は**2048**です。次に、次のようにイメージをマウントします：
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**してみたいですか？または**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**私をフォロー**してください 🐦[@carlospolopm](https://twitter.com/hacktricks_live)**。**
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出して、あなたのハッキングトリックを共有してください。

</details>
