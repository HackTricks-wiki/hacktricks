# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## クイックトリアージ

詳細なコンテンツ解析に入る前に、コンテナレベルの証拠を優先して確認する:

- ファイルを検証し構造を調べる: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- メタデータと可視文字列を抽出する: `exiftool -a -u -g1`, `strings`.
- 埋め込み／末尾追加コンテンツをチェック: `binwalk` とファイル末尾の検査（`tail | xxd`）。
- コンテナごとに分岐:
  - PNG/BMP: bit-planes/LSB and chunk-level anomalies.
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
  - GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### 手法

PNG/BMP は CTF で人気があります。なぜならピクセルを格納する方式が **ビットレベルの操作** を容易にするからです。典型的な隠蔽／抽出の仕組みは次のとおり:

- 各ピクセルチャネル（`R`/`G`/`B`/`A`）は複数のビットを持つ。
- 各チャネルの **最下位ビット** (LSB) は画像をほとんど変化させない。
- 攻撃者はこれらの低位ビットにデータを隠す。場合によってはストライド、置換、チャネルごとの選択を伴うことがある。

チャレンジで予想されること:

- ペイロードは1つのチャネルのみ（例: `R` の LSB）。
- ペイロードがアルファチャネルにある。
- 抽出後にペイロードが圧縮／エンコードされている。
- メッセージが複数のプレーンに分散されている、またはプレーン間でXORされて隠されている。

実装に依存して遭遇する追加の手法:

- **LSB matching** (ビットを単に反転させるのではなく、目標ビットに合わせて +/-1 調整を行う)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (RGB 表示では完全に見えない)

### ツール

#### zsteg

`zsteg` は PNG/BMP 向けの多くの LSB/bit-plane 抽出パターンを列挙します:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 複数の変換を実行します (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: 手動の視覚フィルタ (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFTはLSB抽出ではありません。これはコンテンツが周波数領域や微妙なパターンに故意に隠されている場合に使います。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNGはチャンク化されたフォーマットです。多くのチャレンジではペイロードがピクセル値ではなくコンテナ/チャンクレベルに格納されています:

- **`IEND`の後の余分なバイト** (many viewers ignore trailing bytes)
- **非標準の補助チャンク** がペイロードを運んでいる
- **破損したヘッダ** は寸法を隠したり、修正されるまでパーサを壊すことがある

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
注目すべき点:

- 不審な width/height/bit-depth/colour-type の組み合わせ
- CRC/chunk エラー (pngcheck は通常正確なオフセットを指摘する)
- `IEND` の後に追加データがあるという警告

より詳細な chunk 表示が必要な場合:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Useful references:

- PNG specification（構造、チャンク）: https://www.w3.org/TR/PNG/
- ファイルフォーマットのトリック（PNG/JPEG/GIF の特殊ケース）: https://github.com/corkami/docs

## JPEG: メタデータ、DCT-domain ツール、ELA の制限

### 手法

JPEG は生のピクセルとして保存されず、DCT ドメインで圧縮されます。だから JPEG stego tools は PNG LSB tools と異なります:

- Metadata/comment payloads はファイルレベル（検出しやすく、素早く確認可能）
- DCT-domain stego tools は周波数係数にビットを埋め込みます

運用上、JPEG は次のように扱います:

- メタデータセグメントのコンテナ（検出しやすく、素早く確認可能）
- 圧縮された信号ドメイン（DCT coefficients）で、専門の stego tools が動作する

### クイックチェック
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
有力な格納場所:

- EXIF/XMP/IPTC metadata
- JPEG のコメントセグメント (`COM`)
- アプリケーションセグメント (`APP1` for EXIF, `APPn` for vendor data)

### よく使われるツール

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA は異なる再圧縮アーティファクトを強調表示します。編集された領域を指し示すことがありますが、それ自体は stego 検出器ではありません:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## アニメーション画像

### 手法

アニメーション画像では、メッセージは次のいずれかであると仮定します:

- 単一フレーム内（簡単）、または
- フレームにまたがって分散（順序が重要）、または
- 連続するフレームを diff したときにのみ見える

### フレームを抽出
```bash
ffmpeg -i anim.gif frame_%04d.png
```
その後、フレームを通常のPNGのように扱う: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (高速なフレーム抽出)
- `imagemagick`/`magick` をフレームごとの変換に使用

Frame differencing is often decisive:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## パスワード保護された埋め込み

もし埋め込みが passphrase によって保護されていて、pixel-level manipulation ではないと疑われる場合、通常これが最も速い方法です。

### steghide

`JPEG, BMP, WAV, AU` に対応しており、暗号化されたペイロードを埋め込んだり抽出したりできます。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
リポジトリのファイルに直接アクセスできないため、src/stego/images/README.md の内容をここに貼り付けてください。貼り付けていただければ、指定どおりコードやタグ、リンクをそのままにして、英語テキストのみを日本語に翻訳して返します。
```bash
stegcracker file.jpg wordlist.txt
```
リポジトリ: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV をサポートしています。

リポジトリ: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
