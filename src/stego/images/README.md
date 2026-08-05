# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

ほとんどのCTFにおける画像stegoは、次のいずれかに分類されます。

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunkの異常 / corruption repair
- JPEG DCT-domain tools (OutGuessなど)
- Frame-based (GIF/APNG)

## Quick triage

詳細なcontent analysisを行う前に、container-levelの証拠を優先します。

- ファイルを検証し、構造を調査する: `file`、`magick identify -verbose`、format validators (例: `pngcheck`)。
- Metadataと表示可能なstringsを抽出する: `exiftool -a -u -g1`、`strings`。
- 埋め込みまたは追加されたcontentを確認する: `binwalk`およびファイル末尾の調査 (`tail | xxd`)。
- Containerごとに分岐する:
- PNG/BMP: bit-planes/LSBおよびchunk-levelの異常。
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families)。
- GIF/APNG: frame extraction、frame differencing、palette tricks。

## Bit-planes / LSB

### Technique

PNG/BMPは、pixelsを**bit-level manipulation**しやすい形式で保存するため、CTFでよく使われます。典型的なhide/extractの仕組みは次のとおりです。

- 各pixel channel (R/G/B/A)には複数のbitsがある。
- 各channelの**least significant bit** (LSB)を変更しても、imageへの影響は非常に小さい。
- Attackersはこれらのlow-order bitsにdataを隠します。stride、permutation、またはchannelごとの選択が使われる場合もあります。

challengesで想定されるもの:

- payloadが1つのchannelだけに存在する (例: `R` LSB)。
- payloadがalpha channelに存在する。
- extraction後のpayloadがcompressed/encodedされている。
- messageが複数のplanesに分散している、またはplanes間のXORによって隠されている。

遭遇する可能性があるその他のfamilies (implementation-dependent):

- **LSB matching** (単にbitをflipするのではなく、target bitに合わせるために+/-1のadjustmentsを行う)
- **Palette/index-based hiding** (indexed PNG/GIF: raw RGBではなくcolor indicesにpayloadを格納する)
- **Alpha-only payloads** (RGB viewでは完全に不可視)

### Tooling

#### zsteg

`zsteg`は、PNG/BMP向けに多くのLSB/bit-plane extraction patternsを列挙します。
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: transforms（metadata、image transforms、LSB variantsのbrute forcing）をまとめて実行します。
- `stegsolve`: 手動のvisual filters（channel isolation、plane inspection、XORなど）。

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFTベースのvisibility tricks

FFTはLSB extractionではありません。contentがfrequency spaceや微妙なpatternsに意図的に隠されているケースで使用します。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTFでよく使用されるWebベースのtriage：

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks、corruption、hidden data

### Technique

PNGはchunked formatです。多くのchallengeでは、payloadはpixel valuesではなくcontainer/chunk levelに保存されています：

- **`IEND`後のextra bytes**（多くのviewerはtrailing bytesを無視します）
- **payloadを格納するnon-standard ancillary chunks**
- **dimensionsを隠したり、修正するまでparserを壊したりするcorrupted headers**

確認すべきhigh-signalなchunk locations：

- `tEXt` / `iTXt` / `zTXt`（text metadata、場合によってはcompressed）
- `iCCP`（ICC profile）およびcarrierとして使用されるその他のancillary chunks
- `eXIf`（PNG内のEXIF data）

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
確認する点：

- 奇妙な width/height/bit-depth/colour-type の組み合わせ
- CRC/chunk errors（pngcheck は通常、正確な offset を示します）
- `IEND` の後に追加データがあるという警告

より詳しい chunk の表示が必要な場合：
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Useful references:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata、DCT-domain tools、およびELAの制限

### Technique

JPEGはraw pixelsとして保存されず、DCT domainで圧縮されます。そのため、JPEG stego toolsはPNG LSB toolsとは異なります。

- Metadata/comment payloadsはfile-level（signalが強く、すぐに確認可能）
- DCT-domain stego toolsはfrequency coefficientsにbitsを埋め込む

運用上、JPEGは次のように扱います。

- Metadata segmentsのcontainer（signalが強く、すぐに確認可能）
- specialized stego toolsが動作するcompressed signal domain（DCT coefficients）

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
有力な場所:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments（`APP1` for EXIF、`APPn` for vendor data）

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG 内の steghide payloads に特化して扱う場合は、`stegseek` の使用を検討してください（古い scripts より bruteforce が高速）:

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA は異なる recompression artifacts を強調します。編集された領域を特定する手がかりになりますが、それ自体は stego detector ではありません:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

Animated images では、message が次のいずれかであると想定します:

- 1つの frame 内にある（簡単）
- frames 全体に分散している（ordering が重要）
- 連続する frames の diff でのみ表示される

### Extract frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
その後、フレームを通常の PNG として扱います: `zsteg`、`pngcheck`、チャンネル分離。

代替ツール:

- `gifsicle --explode anim.gif`（高速なフレーム抽出）
- フレームごとの変換には `imagemagick`/`magick`

フレーム差分は決定的な手掛かりになることが多いです:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG コンテナを検出: `exiftool -a -G1 file.png | grep -i animation` または `file`。
- リタイミングせずにフレームを抽出: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- フレームごとのピクセル数として encoded された payloads を復元:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
アニメーション形式の challenge では、各フレーム内の特定の色の数として各バイトをエンコードすることがあります。各フレームのカウントを連結すると、メッセージを復元できます。<sup>[[1]](#references)</sup>

## パスワードで保護された埋め込み

ピクセルレベルの操作ではなく、パスフレーズで保護された embedding が疑われる場合、通常はこれが最も速い方法です。

### steghide

`JPEG, BMP, WAV, AU` をサポートし、暗号化された payload の埋め込みと抽出が可能です。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
リポジトリ: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAVをサポートします。

リポジトリ: https://github.com/dhsdshdhk/stegpy

## 参考資料

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
