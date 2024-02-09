# Stego Tricks

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正を迅速化します。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今すぐ。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **ファイルからデータを抽出する**

### **Binwalk**
埋め込まれた隠しファイルやデータを検索するためのツールです。`apt`を介してインストールされ、そのソースは[GitHub](https://github.com/ReFirmLabs/binwalk)で入手できます。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
ファイルをヘッダーとフッターに基づいて回復し、png画像に便利です。[GitHub](https://github.com/korczis/foremost)でソースを使用して`apt`を介してインストールされます。
```bash
foremost -i file # Extracts data
```
### **Exiftool**
ファイルのメタデータを表示するのに役立ちます。[こちら](https://www.sno.phy.queensu.ca/~phil/exiftool/)で入手できます。
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Exiftoolと同様に、メタデータを表示するためのツールです。`apt`を使用してインストール可能で、[GitHub](https://github.com/Exiv2/exiv2)でソースを入手でき、公式ウェブサイトは[こちら](http://www.exiv2.org/)です。
```bash
exiv2 file # Shows the metadata
```
### **ファイル**
取り扱っているファイルの種類を特定します。

### **文字列**
さまざまなエンコーディング設定を使用して、ファイルから読み取れる文字列を抽出します。
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **比較 (cmp)**
オンラインで見つかった元のバージョンと変更されたファイルを比較するのに便利です。
```bash
cmp original.jpg stego.jpg -b -l
```
## **テキスト内の隠されたデータの抽出**

### **スペース内の隠されたデータ**
見かけ上空白のスペースに不可視の文字が情報を隠しているかもしれません。このデータを抽出するには、[https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) を訪れてください。



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **画像からデータを抽出**

### **GraphicMagickを使用して画像の詳細を特定する**

[GraphicMagick](https://imagemagick.org/script/download.php) は画像ファイルの種類を特定し、潜在的な破損を特定するために役立ちます。以下のコマンドを実行して画像を検査します：
```bash
./magick identify -verbose stego.jpg
```
画像の修復を試みる場合、メタデータコメントを追加すると役立つかもしれません：
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **データの隠蔽にSteghideを使用**

Steghideは、`JPEG、BMP、WAV、およびAU`ファイル内にデータを隠すことを容易にし、暗号化されたデータを埋め込みおよび抽出することができます。`apt`を使用して簡単にインストールでき、[GitHubでソースコードが利用可能です](https://github.com/StefanoDeVuono/steghide)。

**コマンド:**
- `steghide info file`：ファイルに隠されたデータが含まれているかどうかを明らかにします。
- `steghide extract -sf file [--passphrase password]`：隠されたデータを抽出します。パスワードはオプションです。

Webベースの抽出を行う場合は、[このウェブサイト](https://futureboy.us/stegano/decinput.html)を訪れてください。

**Stegcrackerを使用したブルートフォース攻撃:**
- Steghideでパスワードクラッキングを試みるには、[stegcracker](https://github.com/Paradoxis/StegCracker.git)を以下のように使用します:
```bash
stegcracker <file> [<wordlist>]
```
### **PNGおよびBMPファイル用のzsteg**

zstegは、PNGおよびBMPファイル内の隠されたデータを特定することに特化しています。インストールは`gem install zsteg`を使用し、[GitHubでソースを入手](https://github.com/zed-0xff/zsteg)できます。

**コマンド:**
- `zsteg -a file`はファイルにすべての検出方法を適用します。
- `zsteg -E file`はデータ抽出用のペイロードを指定します。

### **StegoVeritasおよびStegsolve**

**stegoVeritas**はメタデータをチェックし、画像変換を実行し、LSBブルートフォースなどを適用します。すべてのオプションの完全なリストには`stegoveritas.py -h`を使用し、すべてのチェックを実行するには`stegoveritas.py stego.jpg`を使用します。

**Stegsolve**はさまざまなカラーフィルタを適用して画像内の隠されたテキストやメッセージを表示します。[GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)で入手できます。

### **隠されたコンテンツの検出のためのFFT**

高速フーリエ変換（FFT）技術を使用すると、画像内の隠されたコンテンツを明らかにすることができます。有用なリソースには次のものがあります：

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [GitHubのFFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **オーディオおよび画像ファイル用のStegpy**

Stegpyを使用すると、PNG、BMP、GIF、WebP、WAVなどの形式をサポートする画像およびオーディオファイルに情報を埋め込むことができます。[GitHub](https://github.com/dhsdshdhk/stegpy)で入手できます。

### **PNGファイルの解析のためのPngcheck**

PNGファイルを解析したり、その信頼性を検証したりするには、
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **画像解析のための追加ツール**

さらなる探求のために、以下を訪れてみてください：

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **オーディオからデータを抽出する**

**オーディオステガノグラフィ**は、音声ファイル内に情報を隠すためのユニークな方法を提供します。異なるツールが埋め込みや隠されたコンテンツの取り出しに使用されます。

### **Steghide (JPEG、BMP、WAV、AU)**
Steghideは、JPEG、BMP、WAV、およびAUファイルにデータを隠すために設計された多目的なツールです。詳細な手順については、[stego tricks documentation](stego-tricks.md#steghide)を参照してください。

### **Stegpy (PNG、BMP、GIF、WebP、WAV)**
このツールは、PNG、BMP、GIF、WebP、およびWAVを含むさまざまな形式と互換性があります。詳細については、[Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)を参照してください。

### **ffmpeg**
ffmpegは、オーディオファイルの整合性を評価し、詳細な情報を強調し、不一致を特定するために重要です。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavStegは、最も重要でないビット戦略を使用してWAVファイル内のデータを隠したり抽出したりするのに優れています。[GitHub](https://github.com/ragibson/Steganography#WavSteg)で利用可能です。コマンドには次のものがあります：
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound allows for the encryption and detection of information within sound files using AES-256. It can be downloaded from [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**
An invaluable tool for visual and analytical inspection of audio files, Sonic Visualizer can unveil hidden elements undetectable by other means. Visit the [official website](https://www.sonicvisualiser.org/) for more.

### **DTMF Tones - Dial Tones**
Detecting DTMF tones in audio files can be achieved through online tools such as [this DTMF detector](https://unframework.github.io/dtmf-detect/) and [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**
Binary data that squares to a whole number might represent a QR code. Use this snippet to check:
```python
import math
math.sqrt(2500) #50
```
### **点字翻訳**
点字を翻訳するには、[Branah点字翻訳](https://www.branah.com/braille-translator)が優れたリソースです。

## **参考文献**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて迅速に修正できるようにしましょう。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリケーション、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今すぐ。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>**ゼロからヒーローまでのAWSハッキングを学ぶ**</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**する
* **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
