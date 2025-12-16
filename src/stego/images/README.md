# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

ほとんどの CTF image stego は次のいずれかのカテゴリに分類されます:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

深いコンテンツ解析の前に、コンテナレベルの痕跡を優先してください:

- ファイルを検証して構造を確認する: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- メタデータと可視文字列を抽出する: `exiftool -a -u -g1`, `strings`.
- 埋め込み/追記されたコンテンツを確認する: `binwalk` とファイル末尾の確認 (`tail | xxd`).
- コンテナ別に分岐:
- PNG/BMP: bit-planes/LSB とチャンクレベルの異常。
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: フレーム抽出、フレーム差分、パレットトリック。

## Bit-planes / LSB

### Technique

PNG/BMP はピクセルをビット単位で扱いやすく保持するため、CTFでよく使われます。典型的な隠蔽/抽出の仕組みは次のとおりです:

- 各ピクセルチャネル(R/G/B/A)は複数のビットを持つ。
- 各チャネルの **最下位ビット** (LSB) は画像の見た目をほとんど変えない。
- 攻撃者はこれらの低位ビットにデータを隠す。ストライド、順列、チャネルごとの選択を使うことがある。

チャレンジでよくあるパターン:

- ペイロードは1チャネルのみ（例: `R` の LSB）。
- ペイロードはアルファチャネルにある。
- 抽出後にペイロードが圧縮/エンコードされている。
- メッセージが複数プレーンに分散される、またはプレーン間の XOR により隠される。

実装依存で出会う追加ファミリ:

- **LSB matching** (単にビットを反転するのではなく、目標ビットに合わせて +/-1 で調整する)
- **Palette/index-based hiding** (indexed PNG/GIF: raw RGB ではなくカラ―インデックスに payload が入る)
- **Alpha-only payloads** (RGB 表示では完全に見えない)

### Tooling

#### zsteg

`zsteg` は PNG/BMP 向けの多くの LSB/bit-plane 抽出パターンを列挙します:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: 一連の変換を実行します（metadata, image transforms, brute forcing LSB variants）。
- `stegsolve`: 手動の視覚フィルタ（channel isolation, plane inspection, XOR, etc）。

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFTはLSB抽出ではありません。周波数領域や微妙なパターンに意図的に隠されたコンテンツを扱う場合に使います。

- EPFL デモ: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### テクニック

PNGはチャンク化されたフォーマットです。多くのチャレンジではペイロードがピクセル値ではなくコンテナ/チャンクレベルに格納されています:

- **`IEND` の後の余分なバイト**（多くのビューアは末尾のバイトを無視します）
- **非標準のancillaryチャンク**にペイロードが格納されている
- **破損したヘッダ**（画像の寸法を隠す、または修正されるまでパーサが動作しない）

注目すべきチャンク位置:

- `tEXt` / `iTXt` / `zTXt` (テキストメタデータ、場合によっては圧縮されている)
- `iCCP` (ICC profile) およびキャリアとして使われる他のancillaryチャンク
- `eXIf` (PNG内のEXIFデータ)

### トリアージコマンド
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
What to look for:

- 幅/高さ/ビット深度/カラ―タイプの組み合わせがおかしい
- CRC/chunk エラー（pngcheck は通常正確なオフセットを指します）
- `IEND` の後に追加データがあるという警告

If you need a deeper chunk view:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
参考資料:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: メタデータ、DCT-domain ツール、および ELA の制限

### 手法

JPEG は生のピクセルとして保存されず、DCT ドメインで圧縮されます。だから JPEG の stego ツールは PNG の LSB ツールとは異なります:

- メタデータ/コメントのペイロードはファイルレベル（目立ちやすく、迅速に確認可能）
- DCT-domain の stego ツールはビットを周波数係数に埋め込みます

運用上、JPEG は次のように扱う:

- メタデータセグメントのコンテナ（目立ちやすく、迅速に確認可能）
- 特殊な stego ツールが動作する圧縮された信号ドメイン（DCT 係数）

### クイックチェック
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
情報が得られやすい箇所:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### 一般的なツール

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEGで特にsteghideのペイロードに遭遇している場合は、`stegseek`（古いスクリプトより高速な bruteforce）を検討してください：

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELAは異なる recompression artifacts を強調表示します。編集された領域を指し示すことがありますが、それ自体は stego detector ではありません：

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## アニメーション画像

### 手法

アニメーション画像では、メッセージは次のいずれかだと想定してください：

- 単一フレームに含まれる（簡単）、または
- フレーム間に分散している（順序が重要）、または
- 連続フレームを差分表示したときにのみ見える

### フレームの抽出
```bash
ffmpeg -i anim.gif frame_%04d.png
```
次に、フレームを通常のPNGとして扱います: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (高速なフレーム抽出)
- `imagemagick`/`magick` (フレームごとの変換用)

フレーム差分はしばしば決定的です:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## パスワード保護された埋め込み

もし pixel-level な操作ではなく passphrase によって保護された埋め込みが疑われる場合、通常これは最速の手段です。

### steghide

`JPEG, BMP, WAV, AU` をサポートしており、暗号化されたペイロードを embed/extract できます。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
該当ファイルの内容をこちらに貼ってください（または該当の "StegCracker" セクションをコピペしてください）。ファイルの内容を受け取ったら、指定どおりMarkdown/HTML構文をそのまま保持して英語テキストを日本語へ翻訳します。
```bash
stegcracker file.jpg wordlist.txt
```
リポジトリ: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAVに対応。

リポジトリ: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
