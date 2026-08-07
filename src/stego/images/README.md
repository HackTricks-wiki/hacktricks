# 画像ステガノグラフィー

{{#include ../../banners/hacktricks-training.md}}

CTF における画像 stego のほとんどは、次のいずれかに分類されます。

- LSB/bit-planes（PNG/BMP）
- Metadata/comment payloads
- PNG chunk の異常 / corruption repair
- JPEG DCT-domain tools（OutGuess など）
- Frame-based（GIF/APNG）

## 初動トリアージ

詳細な content analysis の前に、container-level の証拠を優先します。

- ファイルを検証し、構造を調査します: `file`、`magick identify -verbose`、format validators（例: `pngcheck`）。
- Metadata と表示可能な文字列を抽出します: `exiftool -a -u -g1`、`strings`。
- 埋め込みまたは追記された content を確認します: `binwalk` およびファイル末尾の検査（`tail | xxd`）。
- container に応じて分岐します:
- PNG/BMP: bit-planes/LSB および chunk-level anomalies。
- JPEG: metadata + DCT-domain tooling（OutGuess/F5-style families）。
- GIF/APNG: frame extraction、frame differencing、palette tricks。

## Bit-planes / LSB

### Technique

PNG/BMP は、pixel を **bit-level manipulation** しやすい形式で保存するため、CTF でよく使われます。一般的な hide/extract の仕組みは次のとおりです。

- 各 pixel channel（R/G/B/A）には複数の bit があります。
- 各 channel の **least significant bit**（LSB）を変更しても、画像はほとんど変化しません。
- Attackers は、stride、permutation、または channel ごとの選択を使いながら、これらの low-order bit に data を隠します。

Challenges で想定されるパターン:

- payload が 1 つの channel のみに存在する（例: `R` LSB）。
- payload が alpha channel に存在する。
- 抽出後に payload が compressed/encoded されている。
- message が複数の plane に分散されている、または plane 間の XOR によって隠されている。

遭遇する可能性があるその他の family（implementation-dependent）:

- **LSB matching**（単に bit を反転するのではなく、target bit に合わせるために +/-1 の調整を行う）
- **Palette/index-based hiding**（indexed PNG/GIF で、raw RGB ではなく color index に payload を格納する）
- **Alpha-only payloads**（RGB view では完全に見えない）

### Tooling

#### zsteg

`zsteg` は PNG/BMP に対する多数の LSB/bit-plane extraction patterns を列挙します:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: metadata、image transforms、LSB variants の brute forcing を含む一連の transforms を実行します。
- `stegsolve`: 手動で使用する visual filters（channel isolation、plane inspection、XOR など）。

Stegsolve の download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFTベースの可視化トリック

FFT は LSB extraction ではありません。content が frequency space に意図的に隠されている場合や、微妙な patterns を確認する場合に使用します。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF でよく使用される Web-based triage:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG の internals: chunks、corruption、hidden data

### Technique

PNG は chunked format です。多くの challenge では、payload は pixel values ではなく container/chunk level に保存されています。

- **`IEND` の後にある extra bytes**（多くの viewer は trailing bytes を無視します）
- **payload を含む non-standard ancillary chunks**
- **dimensions を隠したり、修正するまで parsers を壊したりする corrupted headers**

確認すべき signal の高い chunk locations:

- `tEXt` / `iTXt` / `zTXt`（text metadata。一部は compressed）
- `iCCP`（ICC profile）および carrier として使用されるその他の ancillary chunks
- `eXIf`（PNG 内の EXIF data）

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
確認すべき点:

- 不自然な width/height/bit-depth/colour-type の組み合わせ
- CRC/chunk エラー（pngcheck は通常、正確なオフセットを示します）
- `IEND` の後に追加データがあるという警告

より詳細な chunk の表示が必要な場合:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Useful references:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata、DCT-domain tools、ELA の制限

### Technique

JPEG は raw pixels として保存されず、DCT domain で圧縮されます。そのため、JPEG stego tools は PNG LSB tools とは異なります。

- Metadata/comment payloads は file-level です（high-signal で、すばやく確認できます）
- DCT-domain stego tools は frequency coefficients に bits を埋め込みます

Operationally、JPEG は次のように扱います。

- Metadata segments の container（high-signal で、すばやく確認できます）
- Specialized stego tools が動作する compressed signal domain（DCT coefficients）

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA highlights different recompression artifacts; it can point you to regions that were edited, but it’s not a stego detector by itself:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## アニメーション画像

### 手法

アニメーション画像の場合、メッセージは次のいずれかだと想定します。

- 単一のフレーム内にある（簡単）
- フレーム全体に分散している（順序が重要）
- 連続するフレームの差分を取った場合にのみ表示される

### フレームを抽出する
```bash
ffmpeg -i anim.gif frame_%04d.png
```
その後、フレームを通常の PNG として扱います: `zsteg`、`pngcheck`、チャンネル分離。

代替ツール:

- `gifsicle --explode anim.gif`（高速なフレーム抽出）
- フレームごとの変換には `imagemagick`/`magick`

フレーム差分が決定的な手掛かりになることがよくあります:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG コンテナを検出する: `exiftool -a -G1 file.png | grep -i animation` または `file`。
- リタイミングせずにフレームを抽出する: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- フレームごとのピクセル数としてエンコードされた payloads を復元する:
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
Animated challenges では、各フレーム内の特定の色の数として各 byte をエンコードしている場合があります。各フレームのカウントを連結すると、message を復元できます。<sup>[[1]](#references)</sup>

## passphrase で保護された埋め込み

pixel-level manipulation ではなく passphrase によって保護された embedding が疑われる場合、通常はこれが最も速い方法です。

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
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAVに対応。

Repo: https://github.com/dhsdshdhk/stegpy

## 参考資料

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
