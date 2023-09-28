# ステゴトリックス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのスワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有する**ために、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

脆弱性を見つけて修正を迅速に行いましょう。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## すべてのファイルからデータを抽出する

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalkは、画像や音声ファイルなどのバイナリファイルを検索し、埋め込まれた隠しファイルやデータを見つけるためのツールです。\
`apt`を使用してインストールでき、[ソース](https://github.com/ReFirmLabs/binwalk)はGithubで見つけることができます。\
**便利なコマンド**:\
`binwalk file`：指定したファイルに埋め込まれたデータを表示します。\
`binwalk -e file`：指定したファイルからデータを表示して抽出します。\
`binwalk --dd ".*" file`：指定したファイルからデータを表示して抽出します。

### Foremost <a href="#foremost" id="foremost"></a>

Foremostは、ヘッダー、フッター、および内部データ構造に基づいてファイルを回復するプログラムです。特にpng画像を扱う際に非常に便利です。Foremostが抽出するファイルを選択するには、**/etc/foremost.conf**の設定ファイルを変更します。\
`apt`を使用してインストールでき、[ソース](https://github.com/korczis/foremost)はGithubで見つけることができます。\
**便利なコマンド**:\
`foremost -i file`：指定したファイルからデータを抽出します。

### Exiftool <a href="#exiftool" id="exiftool"></a>

時には、重要な情報が画像やファイルのメタデータに隠されていることがあります。exiftoolは、ファイルのメタデータを表示するのに非常に役立ちます。\
[ここから](https://www.sno.phy.queensu.ca/\~phil/exiftool/)入手できます。\
**便利なコマンド**:\
`exiftool file`：指定したファイルのメタデータを表示します。

### Exiv2 <a href="#exiv2" id="exiv2"></a>

exiftoolに似たツールです。\
`apt`を使用してインストールでき、[ソース](https://github.com/Exiv2/exiv2)はGithubで見つけることができます。\
[公式ウェブサイト](http://www.exiv2.org/)\
**便利なコマンド**:\
`exiv2 file`：指定したファイルのメタデータを表示します。

### File

どの種類のファイルかを確認してください。

### Strings

ファイルから文字列を抽出します。\
便利なコマンド:\
`strings -n 6 file`：最小長さ6の文字列を抽出します。\
`strings -n 6 file | head -n 20`：最初の20個の最小長さ6の文字列を抽出します。\
`strings -n 6 file | tail -n 20`：最後の20個の最小長さ6の文字列を抽出します。\
`strings -e s -n 6 file`：7ビット文字列を抽出します。\
`strings -e S -n 6 file`：8ビット文字列を抽出します。\
`strings -e l -n 6 file`：16ビット文字列（リトルエンディアン）を抽出します。\
`strings -e b -n 6 file`：16ビット文字列（ビッグエンディアン）を抽出します。\
`strings -e L -n 6 file`：32ビット文字列（リトルエンディアン）を抽出します。\
`strings -e B -n 6 file`：32ビット文字列（ビッグエンディアン）を抽出します。

### cmp - 比較

**変更された**画像/音声/ビデオがある場合、インターネット上で**元のファイルを正確に見つける**ことができるかどうかを確認し、次のコマンドで両方のファイルを**比較**します。
```
cmp original.jpg stego.jpg -b -l
```
## テキストから隠されたデータを抽出する

### スペースに隠されたデータ

もしもある**テキスト行**が予想よりも**大きい**場合、見えない文字を使って**スペース**の中に**隠された情報**が含まれている可能性があります。󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
データを**抽出**するためには、以下のリンクを使用できます：[https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化されたワークフローを簡単に構築し、自動化することができます。\
今すぐアクセスを取得してください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 画像からデータを抽出する

### identify

[GraphicMagick](https://imagemagick.org/script/download.php)ツールを使用して、ファイルがどの種類の画像であるかを確認します。また、画像が破損しているかどうかも確認します。
```
./magick identify -verbose stego.jpg
```
画像が損傷している場合、メタデータコメントを追加するだけで復元できる場合があります（非常にひどく損傷している場合は機能しないかもしれません）:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghideは、さまざまな種類の画像や音声ファイルにデータを隠すステガノグラフィープログラムです。サポートされているファイル形式は、`JPEG、BMP、WAV、AU`です。また、他のファイルから埋め込まれた暗号化されたデータを抽出するのにも役立ちます。\
`apt`を使用してインストールでき、[ソース](https://github.com/StefanoDeVuono/steghide)はGithubで見つけることができます。\
**便利なコマンド:**\
`steghide info file`：ファイルに埋め込まれたデータの有無についての情報を表示します。\
`steghide extract -sf file [--passphrase password]`：ファイルから埋め込まれたデータを抽出します \[パスワードを使用して]

また、ウェブを使用してsteghideからコンテンツを抽出することもできます：[https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Steghideのブルートフォース攻撃**: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zstegは、pngおよびbmpファイルに隠されたデータを検出するツールです。\
インストール方法：`gem install zsteg`。ソースは[Github](https://github.com/zed-0xff/zsteg)でも見つけることができます。\
**便利なコマンド:**\
`zsteg -a file`：指定したファイルに対してすべての検出方法を実行します。\
`zsteg -E file`：指定したペイロードでデータを抽出します（例：zsteg -E b4,bgr,msb,xy name.png）

### stegoVeritas JPG、PNG、GIF、TIFF、BMP

このツールは、ファイルのメタデータをチェックしたり、変換された画像を作成したり、LSBをブルートフォースしたりするなど、さまざまなシンプルで高度なトリックを実行することができます。完全な機能については、`stegoveritas.py -h`を参照してください。すべてのチェックを実行するには、`stegoveritas.py stego.jpg`を実行します。

### Stegsolve

画像自体にメッセージやテキストが隠されている場合、それを表示するには、カラーフィルタを適用したり、一部のカラーレベルを変更したりする必要があります。GIMPやPhotoshopのようなツールを使用してこれを行うこともできますが、Stegsolveを使用すると簡単になります。これは、画像に多くの便利なカラーフィルタを適用する小さなJavaツールです。CTFの課題では、Stegsolveはしばしば本当の時間節約者です。\
[GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)から入手できます。\
使用するには、画像を開き、`<` `>`ボタンをクリックします。

### FFT

Fast Fourier Tを使用して隠されたコンテンツを検出するには：

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

ステガノグラフィを使用して画像や音声ファイルに情報をエンコードするためのプログラムです。データは平文または暗号化として保存することができます。\
[GitHub](https://github.com/dhsdshdhk/stegpy)で見つけることができます。

### Pngcheck

PNGファイルの詳細を取得します（または実際には別のファイルであることを確認します）。\
`apt-get install pngcheck`：ツールをインストールします。\
`pngcheck stego.png`：PNGに関する情報を取得します。

### その他の言及に値する画像ツール

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## オーディオからデータを抽出する

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpegは、オーディオファイルの整合性をチェックし、ファイルに関するさまざまな情報やエラーを報告するために使用できます。\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavStegは、wavファイルに最下位ビットを使用してデータを隠すことができるPython3ツールです。また、wavファイルからデータを検索および抽出することもできます。\
[GitHub](https://github.com/ragibson/Steganography#WavSteg)から入手できます。\
便利なコマンド：\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile`：出力ファイルに抽出します（最下位ビットのみを取得）\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile`：出力ファイルに抽出します（最下位2ビットのみを取得）

### Deepsound

音声ファイルにAES-265で暗号化された情報を隠したり、検索したりすることができます。[公式ページ](http://jpinsoft.net/deepsound/download.aspx)からダウンロードしてください。\
隠された情報を検索するには、プログラムを実行して音声ファイルを開きます。DeepSoundが隠されたデータを見つけた場合、解除するためのパスワードが必要です。

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizerは、オーディオファイルの内容を表示および分析するためのツールです。オーディオステガノグラフィの課題に直面した場合、他の多くのツールでは検出できないオーディオファイルの隠れた形状を明らかにすることができます。\
行き詰まった場合は、常にオーディオのスペクトログラムをチェックしてください。[公式ウェブサイト](https://www.sonicvisualiser.org/)

### DTMF Tones - ダイヤル音

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)
## その他のトリック

### 2進数の長さSQRT - QRコード

もし、整数の平方根の長さを持つ2進数データを受け取った場合、それはQRコードの一種かもしれません。
```
import math
math.sqrt(2500) #50
```
バイナリの「1」と「0」を適切な画像に変換するには：[https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
QRコードを読み取るには：[https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### ブライユ

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **参考文献**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できます。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまでクラウドシステム全体にわたる問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
