# Stego Tricks

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

重要な脆弱性を素早く見つけて修正する。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまでの技術スタック全体で問題を見つけます。今日[**無料で試す**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## すべてのファイルからデータを抽出する

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalkは、画像やオーディオファイルなどのバイナリファイルを検索し、埋め込まれた隠しファイルやデータを検出するツールです。\
`apt`でインストールでき、[ソース](https://github.com/ReFirmLabs/binwalk)はGithubで見つけることができます。\
**便利なコマンド**:\
`binwalk file` : 指定されたファイルに埋め込まれたデータを表示します\
`binwalk -e file` : 指定されたファイルからデータを表示し、抽出します\
`binwalk --dd ".*" file` : 指定されたファイルからデータを表示し、抽出します

### Foremost <a href="#foremost" id="foremost"></a>

Foremostは、ヘッダー、フッター、および内部データ構造に基づいてファイルを復元するプログラムです。特にpng画像を扱う際に非常に役立つと感じています。**/etc/foremost.conf**の設定ファイルを変更することで、Foremostが抽出するファイルを選択できます。\
`apt`でインストールでき、[ソース](https://github.com/korczis/foremost)はGithubで見つけることができます。\
**便利なコマンド:**\
`foremost -i file` : 指定されたファイルからデータを抽出します。

### Exiftool <a href="#exiftool" id="exiftool"></a>

時には、重要な情報が画像やファイルのメタデータに隠されていることがあります。exiftoolはファイルメタデータを表示するのに非常に役立ちます。\
[こちら](https://www.sno.phy.queensu.ca/\~phil/exiftool/)から入手できます。\
**便利なコマンド:**\
`exiftool file` : 指定されたファイルのメタデータを表示します

### Exiv2 <a href="#exiv2" id="exiv2"></a>

exiftoolに似たツールです。\
`apt`でインストールでき、[ソース](https://github.com/Exiv2/exiv2)はGithubで見つけることができます。\
[公式ウェブサイト](http://www.exiv2.org/)\
**便利なコマンド:**\
`exiv2 file` : 指定されたファイルのメタデータを表示します

### File

どのような種類のファイルを持っているかを確認します。

### Strings

ファイルから文字列を抽出します。\
便利なコマンド:\
`strings -n 6 file`: 最小長6の文字列を抽出します\
`strings -n 6 file | head -n 20`: 最小長6の最初の20文字列を抽出します\
`strings -n 6 file | tail -n 20`: 最小長6の最後の20文字列を抽出します\
`strings -e s -n 6 file`: 7ビット文字列を抽出します\
`strings -e S -n 6 file`: 8ビット文字列を抽出します\
`strings -e l -n 6 file`: 16ビット文字列を抽出します（リトルエンディアン）\
`strings -e b -n 6 file`: 16ビット文字列を抽出します（ビッグエンディアン）\
`strings -e L -n 6 file`: 32ビット文字列を抽出します（リトルエンディアン）\
`strings -e B -n 6 file`: 32ビット文字列を抽出します（ビッグエンディアン）

### cmp - 比較

**変更された**画像/オーディオ/ビデオを持っている場合、インターネット上で**正確なオリジナルを見つける**ことができるかどうかを確認し、次に両方のファイルを以下で**比較**します：
```
cmp original.jpg stego.jpg -b -l
```
## テキスト内の隠されたデータの抽出

### スペース内の隠されたデータ

もし**テキスト行**が通常よりも**大きい**場合、**スペース**内に不可視文字を使って**隠された情報**が含まれている可能性があります。󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
**データ**を**抽出**するには、次のツールを使用できます: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で**最も高度な**コミュニティツールによって動力を供給される**ワークフローを簡単に構築し自動化**します。\
今すぐアクセス:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 画像からのデータ抽出

### identify

[GraphicMagick](https://imagemagick.org/script/download.php)は、ファイルがどのような画像かを確認するツールです。画像が破損していないかもチェックします。
```
./magick identify -verbose stego.jpg
```
```markdown
画像が損傷している場合、メタデータコメントを追加するだけで修復できることがあります（非常に悪い状態の場合は機能しません）：
```
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghideは、画像ファイルやオーディオファイルにデータを隠すステガノグラフィープログラムです。対応しているファイル形式は `JPEG, BMP, WAV, AU` です。また、他のファイルから埋め込まれた暗号化されたデータを抽出するのにも役立ちます。\
`apt` でインストール可能で、[ソース](https://github.com/StefanoDeVuono/steghide)はGithubで見つけることができます。\
**便利なコマンド:**\
`steghide info file` : ファイルに埋め込まれたデータがあるかどうかの情報を表示します。\
`steghide extract -sf file [--passphrase password]` : ファイルから埋め込まれたデータを抽出します \[パスワード使用]

Steghideの内容もウェブを使って抽出できます: [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Bruteforcing** Steghide: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zstegは、pngとbmpファイルに隠されたデータを検出するツールです。\
インストール方法: `gem install zsteg`。ソースも[Github](https://github.com/zed-0xff/zsteg)で見つけることができます。\
**便利なコマンド:**\
`zsteg -a file` : 指定されたファイルに対してすべての検出方法を実行します。\
`zsteg -E file` : 指定されたペイロードでデータを抽出します (例 : zsteg -E b4,bgr,msb,xy name.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

ファイルメタデータのチェック、変換された画像の作成、LSBのブルートフォースなど、シンプルから高度なトリックまで幅広く対応するツールです。`stegoveritas.py -h` を実行して、その全機能について読んでください。`stegoveritas.py stego.jpg` を実行して、すべてのチェックを行います。

### Stegsolve

画像自体に隠されたメッセージやテキストがあり、それを見るためには色フィルターを適用したり、色のレベルを変更する必要があります。GIMPやPhotoshopのようなものでこれを行うことができますが、Stegsolveはそれを簡単にします。これは、画像に多くの便利な色フィルターを適用する小さなJavaツールです。CTFチャレンジでは、Stegsolveはしばしば本当の時間節約になります。\
[Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)から入手できます。\
使用するには、画像を開いて `<` `>` ボタンをクリックします。

### FFT

高速フーリエ変換を使用して隠されたコンテンツを見つけるには:

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

画像ファイルやオーディオファイルに情報をエンコードするためのステガノグラフィープログラムです。データはプレーンテキストまたは暗号化された形式で保存できます。\
[Github](https://github.com/dhsdshdhk/stegpy)で見つけることができます。

### Pngcheck

PNGファイルの詳細を取得します（実際には別のものであることもわかります！）。\
`apt-get install pngcheck`: ツールをインストールします。\
`pngcheck stego.png` : PNGに関する情報を取得します。

### その他の画像ツールの言及に値するもの

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [https://github.com/resurrecting-open-source-projects/outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [https://www.openstego.com/](https://www.openstego.com/)
* [https://diit.sourceforge.net/](https://diit.sourceforge.net/)

## オーディオからデータを抽出する

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpegはオーディオファイルの整合性をチェックし、ファイルに関する様々な情報や見つかったエラーを報告するのに使用できます。\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavStegはPython3ツールで、wavファイルにデータを隠すことができます。また、wavファイルからデータを検索し、抽出することもできます。\
[Github](https://github.com/ragibson/Steganography#WavSteg)から入手できます。\
便利なコマンド:\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : 出力ファイルに抽出します（1 lsbのみを取ります）。\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : 出力ファイルに抽出します（2 lsbのみを取ります）。

### Deepsound

AES-265で暗号化された情報をサウンドファイルに隠し、チェックします。[公式ページ](http://jpinsoft.net/deepsound/download.aspx)からダウンロードしてください。\
隠された情報を検索するには、プログラムを実行してサウンドファイルを開くだけです。DeepSoundが隠されたデータを見つけた場合、それを解除するためのパスワードを提供する必要があります。

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizerはオーディオファイルの内容を視覚化し分析するツールです。オーディオステガノグラフィーチャレンジに直面したときに非常に役立ちます。多くの他のツールでは検出されないオーディオファイル内の隠された形を明らかにすることができます。\
詰まったら、常にオーディオのスペクトログラムをチェックしてください。[公式ウェブサイト](https://www.sonicvisualiser.org/)

### DTMF Tones - Dial tones

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## その他のトリック

### Binary length SQRT - QR Code

全体の数のSQRT長さのバイナリデータを受け取った場合、それは何らかのQRコードである可能性があります：
```
import math
math.sqrt(2500) #50
```
バイナリの "1" と "0" を適切な画像に変換するには: [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
QRコードを読むには: [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### ブライユ

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **参考文献**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正しましょう。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまでの技術スタック全体で問題を見つけます。今日[**無料でお試し**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローに学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
