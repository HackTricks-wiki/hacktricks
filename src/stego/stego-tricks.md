# ステゴトリック

{{#include ../banners/hacktricks-training.md}}

## **ファイルからのデータ抽出**

### **Binwalk**

埋め込まれた隠しファイルやデータを探すためのバイナリファイル検索ツールです。`apt`を介してインストールされ、ソースは[GitHub](https://github.com/ReFirmLabs/binwalk)で入手可能です。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

ヘッダーとフッターに基づいてファイルを回復し、png画像に便利です。`apt`を介してインストールされ、そのソースは[GitHub](https://github.com/korczis/foremost)にあります。
```bash
foremost -i file # Extracts data
```
### **Exiftool**

ファイルメタデータを表示するのに役立ちます。利用可能なリンクは[こちら](https://www.sno.phy.queensu.ca/~phil/exiftool/)です。
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftoolと同様に、メタデータの表示に使用されます。`apt`を介してインストール可能で、ソースは[GitHub](https://github.com/Exiv2/exiv2)にあり、[公式ウェブサイト](http://www.exiv2.org/)があります。
```bash
exiv2 file # Shows the metadata
```
### **ファイル**

扱っているファイルの種類を特定します。

### **文字列**

さまざまなエンコーディング設定を使用して、ファイルから読み取り可能な文字列を抽出します。
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

オンラインで見つかった元のバージョンと修正されたファイルを比較するのに便利です。
```bash
cmp original.jpg stego.jpg -b -l
```
## **テキスト内の隠されたデータの抽出**

### **スペース内の隠されたデータ**

見た目には空のスペースに隠された情報があるかもしれません。このデータを抽出するには、[https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)を訪れてください。

## **画像からのデータの抽出**

### **GraphicMagickを使用した画像の詳細の特定**

[GraphicMagick](https://imagemagick.org/script/download.php)は、画像ファイルの種類を特定し、潜在的な破損を識別するために使用されます。画像を検査するには、以下のコマンドを実行してください：
```bash
./magick identify -verbose stego.jpg
```
損傷した画像の修復を試みるために、メタデータコメントを追加することが役立つかもしれません:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **データ隠蔽のためのSteghide**

Steghideは、`JPEG, BMP, WAV, AU`ファイル内にデータを隠すことを容易にし、暗号化されたデータの埋め込みと抽出が可能です。インストールは`apt`を使用して簡単に行え、[ソースコードはGitHubで入手可能です](https://github.com/StefanoDeVuono/steghide)。

**コマンド:**

- `steghide info file`は、ファイルに隠されたデータが含まれているかどうかを明らかにします。
- `steghide extract -sf file [--passphrase password]`は、隠されたデータを抽出します。パスワードはオプションです。

ウェブベースの抽出については、[このウェブサイト](https://futureboy.us/stegano/decinput.html)を訪れてください。

**Stegcrackerによるブルートフォース攻撃:**

- Steghideのパスワードクラッキングを試みるには、[stegcracker](https://github.com/Paradoxis/StegCracker.git)を次のように使用します:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zstegはPNGおよびBMPファイル内の隠れたデータを発見することに特化しています。インストールは`gem install zsteg`で行い、[GitHubのソース](https://github.com/zed-0xff/zsteg)があります。

**Commands:**

- `zsteg -a file`はファイルに対してすべての検出方法を適用します。
- `zsteg -E file`はデータ抽出のためのペイロードを指定します。

### **StegoVeritas and Stegsolve**

**stegoVeritas**はメタデータをチェックし、画像変換を行い、LSBブルートフォースなどの機能を適用します。オプションの完全なリストは`stegoveritas.py -h`を使用し、すべてのチェックを実行するには`stegoveritas.py stego.jpg`を使用します。

**Stegsolve**はさまざまなカラーフィルターを適用して、画像内の隠れたテキストやメッセージを明らかにします。これは[GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)で入手可能です。

### **FFT for Hidden Content Detection**

高速フーリエ変換（FFT）技術は、画像内の隠されたコンテンツを明らかにすることができます。役立つリソースには以下が含まれます：

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpyは、PNG、BMP、GIF、WebP、WAVなどの形式をサポートし、画像および音声ファイルに情報を埋め込むことを可能にします。これは[GitHub](https://github.com/dhsdshdhk/stegpy)で入手可能です。

### **Pngcheck for PNG File Analysis**

PNGファイルを分析するか、その真正性を検証するには、次のコマンドを使用します：
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **画像分析のための追加ツール**

さらなる探索のために、以下を訪れることを検討してください：

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **オーディオからのデータ抽出**

**オーディオステガノグラフィ**は、音声ファイル内に情報を隠すユニークな方法を提供します。隠されたコンテンツを埋め込むまたは取得するために、さまざまなツールが利用されます。

### **Steghide (JPEG, BMP, WAV, AU)**

Steghideは、JPEG、BMP、WAV、およびAUファイルにデータを隠すために設計された多目的ツールです。詳細な指示は[stego tricks documentation](stego-tricks.md#steghide)に記載されています。

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

このツールは、PNG、BMP、GIF、WebP、およびWAVを含むさまざまなフォーマットに対応しています。詳細については、[Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)を参照してください。

### **ffmpeg**

ffmpegは、オーディオファイルの整合性を評価するために重要であり、詳細な情報を強調し、いかなる不一致を特定します。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavStegは、最下位ビット戦略を使用してWAVファイル内にデータを隠蔽および抽出するのに優れています。これは[GitHub](https://github.com/ragibson/Steganography#WavSteg)で入手可能です。コマンドには次のものが含まれます:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsoundは、AES-256を使用して音声ファイル内の情報を暗号化および検出することを可能にします。 [公式ページ](http://jpinsoft.net/deepsound/download.aspx)からダウンロードできます。

### **Sonic Visualizer**

音声ファイルの視覚的および分析的検査において非常に貴重なツールであるSonic Visualizerは、他の手段では検出できない隠れた要素を明らかにすることができます。 詳細は[公式ウェブサイト](https://www.sonicvisualiser.org/)をご覧ください。

### **DTMF Tones - Dial Tones**

音声ファイル内のDTMFトーンを検出するには、[このDTMF検出器](https://unframework.github.io/dtmf-detect/)や[DialABC](http://dialabc.com/sound/detect/index.html)などのオンラインツールを使用できます。

## **Other Techniques**

### **Binary Length SQRT - QR Code**

整数に平方するバイナリデータはQRコードを表す可能性があります。このスニペットを使用して確認してください：
```python
import math
math.sqrt(2500) #50
```
バイナリから画像への変換については、[dcode](https://www.dcode.fr/binary-image)を確認してください。QRコードを読むには、[このオンラインバーコードリーダー](https://online-barcode-reader.inliteresearch.com/)を使用してください。

### **点字翻訳**

点字の翻訳には、[Branah Braille Translator](https://www.branah.com/braille-translator)が優れたリソースです。

## **参考文献**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
