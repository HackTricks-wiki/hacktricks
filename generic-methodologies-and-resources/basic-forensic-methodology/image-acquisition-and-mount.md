# イメージの取得とマウント

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## 取得

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd is an enhanced version of the dd command, specifically designed for forensic imaging tasks. It provides additional features and options that are useful for acquiring and copying disk images.

dcfldd can be used to acquire disk images from both physical and logical devices. It supports various input and output formats, including raw, EWF (Expert Witness Format), and AFF (Advanced Forensic Format).

To acquire an image using dcfldd, you need to specify the input and output devices or files. You can also set options such as block size, hash algorithm, and progress reporting.

Here is the basic syntax for acquiring an image with dcfldd:

```
dcfldd if=<input> of=<output> [options]
```

Some commonly used options include:

- `bs`: Specifies the block size for reading and writing data.
- `hash`: Specifies the hash algorithm to use for verifying the integrity of the image.
- `hashwindow`: Specifies the size of the hash window.
- `hashlog`: Specifies the file to store the hash values.
- `statusinterval`: Specifies the interval for displaying progress status.

For example, to acquire an image from a physical device and calculate the MD5 hash, you can use the following command:

```
dcfldd if=/dev/sda of=image.dd hash=md5
```

dcfldd is a powerful tool for acquiring disk images in a forensic investigation. It provides advanced features and options that can help ensure the integrity and accuracy of the acquired images.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTKイメージャー

[**ここからFTKイメージャーをダウンロードできます**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1)。
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

[**ewfツール**](https://github.com/libyal/libewf)を使用してディスクイメージを生成することができます。
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

**Windows**では、無料版のArsenal Image Mounter（[https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)）を使用して、**フォレンジックイメージをマウント**することができます。

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF（EnCase Evidence File）は、ディスクイメージの作成と分析に使用されるフォレンジックファイルフォーマットです。EWFフォーマットは、ディスクのセクタ単位でデータを取得し、証拠の整合性を保つためにハッシュ値を使用します。

EWFファイルを作成するには、次の手順を実行します。

1. EWFファイルの作成に使用するディスクを特定します。
2. EWFファイルの作成方法を選択します。例えば、物理ディスク、論理ディスク、またはファイルとして作成することができます。
3. EWFファイルの作成時に使用するハッシュアルゴリズムを選択します。一般的なアルゴリズムには、MD5、SHA-1、SHA-256などがあります。
4. EWFファイルの作成を開始します。

EWFファイルをマウントするには、次の手順を実行します。

1. EWFファイルをマウントするためのディレクトリを作成します。
2. EWFファイルを指定してマウントコマンドを実行します。マウントコマンドは、使用しているオペレーティングシステムによって異なる場合があります。
3. マウントが成功したら、指定したディレクトリにアクセスしてファイルを分析することができます。

EWFフォーマットは、ディスクイメージの作成と分析において広く使用されています。証拠の整合性を保ちながらデータを取得するため、フォレンジック調査において信頼性の高い手法とされています。
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

これは、ボリュームをマウントするためのWindowsアプリケーションです。[ここからダウンロードできます](https://arsenalrecon.com/downloads/)

### エラー

* **`cannot mount /dev/loop0 read-only`** この場合、フラグ **`-o ro,norecovery`** を使用する必要があります。
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** この場合、マウントに失敗しました。ファイルシステムのオフセットがディスクイメージと異なるためです。セクターサイズと開始セクターを見つける必要があります。
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
セクターサイズは**512**で、開始位置は**2048**です。次のようにイメージをマウントします：
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
