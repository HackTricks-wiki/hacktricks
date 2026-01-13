# 画像ステガノグラフィ

{{#include ../../banners/hacktricks-training.md}}

ほとんどのCTFの画像ステガノグラフィは、次のいずれかのカテゴリに分類されます：

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

コンテンツを深掘りする前に、まずコンテナレベルの証拠を優先してください：

- ファイルを検証して構造を確認： `file`, `magick identify -verbose`, フォーマット検証ツール（例：`pngcheck`）。
- メタデータと可視文字列を抽出： `exiftool -a -u -g1`, `strings`。
- 埋め込み/末尾追記コンテンツを確認： `binwalk` とファイル末尾の検査（`tail | xxd`）。
- コンテナ別に分岐：
  - PNG/BMP: bit-planes/LSB とチャンクレベルの異常。
  - JPEG: メタデータ + DCT-domain ツール（OutGuess/F5系）。
  - GIF/APNG: フレーム抽出、フレーム差分、パレットトリック。

## Bit-planes / LSB

### Technique

PNG/BMP はピクセルをビット単位で扱う構造を持つため、CTFでよく使われます。典型的な隠蔽/抽出の仕組みは以下の通りです：

- 各ピクセルのチャンネル（R/G/B/A）は複数のビットを持つ。
- 各チャンネルの最下位ビット（LSB）は画像をほとんど変化させない。
- 攻撃者はそれらの低位ビットにデータを隠す。時にはストライド、置換、チャンネルごとの選択を使う。

チャレンジで期待されること：

- ペイロードは単一チャンネルだけにある（例：`R` の LSB）。
- ペイロードはアルファチャネルにある。
- 抽出後にペイロードが圧縮/エンコードされている。
- メッセージが複数プレーンに分散されている、あるいはプレーン間でXORされた形で隠されている。

実装依存で出会う追加のファミリ：

- **LSB matching**（単にビットを反転するのではなく、目標ビットに合わせて +/-1 調整する手法）
- **Palette/index-based hiding**（indexed PNG/GIF：生のRGBではなく色インデックスにペイロードを格納）
- **Alpha-only payloads**（RGBビューでは完全に不可視）

### Tooling

#### zsteg

`zsteg` は PNG/BMP 向けの多くのLSB/bit-plane抽出パターンを列挙します：
```bash
zsteg -a file.png
```
リポジトリ: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: メタデータ、画像変換、LSBバリアントの総当たりなどの一連の変換を実行します。
- `stegsolve`: チャネル分離、プレーン検査、XOR 等の手動視覚フィルタ。

Stegsolve ダウンロード: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFTはLSB抽出とは異なり、周波数領域や微妙なパターンに意図的に隠されたコンテンツに対して用います。

- EPFL デモ: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTFでよく使われるWebベースのトリアージ:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### 技法

PNGはチャンク形式です。多くのチャレンジでは、ペイロードはピクセル値ではなくコンテナ/チャンクレベルに格納されます:

- **`IEND`の後の余分なバイト**（多くのビューワは末尾のバイトを無視します）
- **ペイロードを含む非標準の補助チャンク**
- **画像の寸法を隠したり、修正されるまでパーサを壊す破損したヘッダ**

注目すべきチャンク位置:

- `tEXt` / `iTXt` / `zTXt`（テキストメタデータ、時に圧縮）
- `iCCP`（ICCプロファイル）やキャリアとして使われる他の補助チャンク
- `eXIf`（PNG内のEXIFデータ）

### トリアージコマンド
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
確認すべき項目:

- 幅/高さ/ビット深度/カラーモードの異常な組み合わせ
- CRC/チャンクエラー（pngcheck は通常正確なオフセットを示します）
- `IEND` の後に追加データがあるという警告

より詳細なチャンク表示が必要な場合:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
参考資料:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### 手法

JPEG は生のピクセルとして保存されるのではなく、DCT ドメインで圧縮されます。だからこそ JPEG の stego ツールは PNG の LSB ツールと異なります:

- Metadata/comment payloads はファイルレベル（情報量が高く素早く確認できる）
- DCT-domain stego tools はビットを frequency coefficients に埋め込みます

実務上、JPEG は次のように扱います:

- metadata segments のコンテナ（情報量が高く素早く確認できる）
- 特殊な stego ツールが動作する、圧縮された信号ドメイン（DCT coefficients）

### 簡易チェック
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:
- EXIF/XMP/IPTC メタデータ
- JPEGのコメントセグメント (`COM`)
- アプリケーションセグメント（`APP1` は EXIF、`APPn` はベンダーデータ）

### 共通ツール

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA は異なる再圧縮アーティファクトを強調表示します；編集された領域を示すことがありますが、それ自体は stego detector ではありません:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## アニメーション画像

### 手法

アニメーション画像では、メッセージは次のいずれかと仮定します:

- 単一フレームにある（簡単）、または
- フレームにまたがっている（順序が重要）、または
- 連続するフレームを diff したときにのみ見える

### フレームの抽出
```bash
ffmpeg -i anim.gif frame_%04d.png
```
次に、フレームを通常のPNGのように扱います: `zsteg`, `pngcheck`, channel isolation.

代替ツール:

- `gifsicle --explode anim.gif` (高速なフレーム抽出)
- `imagemagick`/`magick` (フレームごとの変換用)

フレーム差分はしばしば決定的です:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNGコンテナを検出: `exiftool -a -G1 file.png | grep -i animation` または `file`.
- 再タイミングせずにフレームを抽出: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- フレームごとのピクセル数でエンコードされたpayloadsを復元:
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
アニメーションされたチャレンジは、各フレームで特定の色の出現回数を各バイトとして符号化することがある。出現回数を連結するとメッセージが復元される。

## パスワード保護された埋め込み

ピクセルレベルの操作ではなくpassphraseで保護された埋め込みが疑われる場合、通常これが最速の手段です。

### steghide

`JPEG, BMP, WAV, AU` に対応し、暗号化されたペイロードの埋め込み/抽出が可能です。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
ファイルの内容（src/stego/images/README.md）をここに貼ってください。貼っていただければ、指定どおりマークダウンやタグ・リンクをそのまま保持して、英語の本文を日本語に翻訳して返します。
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV に対応。

Repo: https://github.com/dhsdshdhk/stegpy

## 参考資料

- [Flagvent 2025 (Medium) — pink、サンタのウィッシュリスト、クリスマスのメタデータ、キャプチャされたノイズ](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
