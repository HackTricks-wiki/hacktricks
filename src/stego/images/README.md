# 画像ステガノグラフィ

{{#include ../../banners/hacktricks-training.md}}

多くのCTF画像ステガノグラフィは、次のいずれかに分類されます。

- LSB/ビットプレーン（PNG/BMP）
- メタデータ/コメントのペイロード
- PNGチャンクの異常/破損の修復
- JPEG DCT領域のツール（OutGuessなど）
- フレームベース（GIF/APNG）

## 迅速な初期調査

詳細なコンテンツ解析の前に、コンテナレベルの証拠を優先して確認します。

- ファイルの検証と構造の確認: `file`、`magick identify -verbose`、形式検証ツール（例: `pngcheck`）。
- メタデータと可視文字列の抽出: `exiftool -a -u -g1`、`strings`。
- 埋め込み/追加コンテンツの確認: `binwalk` とファイル末尾の調査（`tail | xxd`）。
- コンテナに応じて調査方法を切り替えます:
  - PNG/BMP: ビットプレーン/LSBとチャンクレベルの異常。
  - JPEG: メタデータとDCT領域のツール（OutGuess/F5系）。
  - GIF/APNG: フレーム抽出、フレーム差分、パレットのトリック。

## ビットプレーン / LSB

### 技法

PNG/BMPは、ピクセルを**ビット単位で操作**しやすい形式で保存するため、CTFでよく使われます。典型的な隠蔽/抽出の仕組みは次のとおりです。

- 各ピクセルのチャンネル（R/G/B/A）には複数のビットがあります。
- 各チャンネルの**最下位ビット**（LSB）を変更しても、画像への影響はごくわずかです。
- 攻撃者は、ストライド、順列、チャンネル選択などを使い、これらの下位ビットにデータを隠します。

チャレンジで想定されるもの:

- ペイロードが1つのチャンネルのみにある（例: `R` のLSB）。
- ペイロードがアルファチャンネルにある。
- 抽出後にペイロードが圧縮/エンコードされている。
- メッセージが複数のプレーンに分散されている、またはプレーン間のXORで隠されている。

遭遇する可能性のあるその他の方式（実装による）:

- **LSB matching**（ビットを反転するだけでなく、目標のビットに合わせて値を+/-1する）
- **パレット/インデックスベースの隠蔽**（インデックス付きPNG/GIFで、raw RGBではなく色インデックスにペイロードを隠す）
- **アルファのみのペイロード**（RGB表示では完全に見えない）

### ツール

#### zsteg

`zsteg`は、PNG/BMP向けのさまざまなLSB/ビットプレーン抽出パターンを列挙します。

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 一連の変換処理を実行します（メタデータ、画像変換、LSB variants の brute force）。
- `stegsolve`: 手動で視覚フィルターを適用します（チャンネルの分離、plane の検査、XOR など）。

Stegsolve のダウンロード: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT を使った可視化のテクニック

FFT は LSB extraction ではありません。周波数空間に意図的に隠されたコンテンツや、微細なパターンを扱う場合に使用します。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF でよく使われる Web ベースのトリアージツール:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG の内部構造: chunks、破損、隠しデータ

### Technique

PNG は chunk で構成される形式です。多くのチャレンジでは、payload はピクセル値ではなく、コンテナや chunk のレベルに格納されています。

- **`IEND` の後にある余分なバイト**（多くのビューアは末尾のバイトを無視します）
- **payload を含む非標準の ancillary chunks**。詳しくは [PNG chunk walker and carving workflow](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads) を参照してください。
- **破損したヘッダー**。寸法を隠したり、修正するまで parser を動作させない場合があります。

優先して確認する chunk の場所:

- `tEXt` / `iTXt` / `zTXt`（テキストメタデータ。圧縮されている場合もあります）
- `iCCP`（ICC profile）や、carrier として使われるその他の ancillary chunks
- `eXIf`（PNG 内の EXIF data）

### トリアージ用コマンド

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

確認する項目:

- 幅/高さ/bit-depth/colour-typeの不自然な組み合わせ
- CRC/chunkのエラー（pngcheckは通常、正確なオフセットを示します）
- `IEND`の後に追加データがあるという警告

chunkを詳しく確認するには:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

参考資料:

- PNG仕様（構造、チャンク）: https://www.w3.org/TR/PNG/
- ファイル形式のテクニック（PNG/JPEG/GIFの特殊ケース）: https://github.com/corkami/docs

## JPEG: メタデータ、DCT-domainツール、ELAの限界

### Technique

JPEGは生のピクセルとして保存されず、DCT domainで圧縮されます。そのため、JPEG stegoツールはPNG LSBツールとは異なります。

- メタデータ/コメントのペイロードはファイルレベルにあるため、優先度が高く、すばやく調査できます
- DCT-domain stegoツールは、周波数係数にビットを埋め込みます

実際の運用では、JPEGを次のように扱います。

- メタデータセグメントのコンテナ（優先度が高く、すばやく調査できる）
- 専用のstegoツールが動作する圧縮信号 domain（DCT係数）

### Quick checks

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

信号の強い場所:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments（EXIF用の`APP1`、vendor data用の`APPn`）

### 一般的なツール

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG内のsteghide payloadsを調べる場合は、`stegseek`の使用を検討してください（旧式のスクリプトよりbruteforceが高速です）:

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELAは異なる再圧縮アーティファクトを強調表示します。編集された領域の特定に役立つことがありますが、それ自体はstego detectorではありません:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## アニメーション画像

### 手法

アニメーション画像では、メッセージが次のいずれかに含まれていると考えてください:

- 単一のフレーム（簡単）
- フレーム間に分散（順序が重要）
- 連続するフレームをdiffしたときにのみ見える

### フレームの抽出

```bash
ffmpeg -i anim.gif frame_%04d.png
```

その後、フレームを通常の PNG として扱います: `zsteg`、`pngcheck`、チャンネル分離。

代替ツール:

- `gifsicle --explode anim.gif`（高速なフレーム抽出）
- フレームごとの変換には `imagemagick`/`magick`

フレーム差分が決め手になることもよくあります:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNGのピクセル数エンコーディング

- APNGコンテナを検出する: `exiftool -a -G1 file.png | grep -i animation` または `file`。
- タイミングを変更せずにフレームを抽出する: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- フレームごとのピクセル数としてエンコードされたペイロードを復元する:

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

アニメーション形式のチャレンジでは、各フレーム内の特定の色の数を各バイトとして符号化している場合があります。各フレームの数を連結すると、メッセージを復元できます。<sup>[[1]](#references)</sup>

## パスワード保護された埋め込み

ピクセル単位の操作ではなく、パスフレーズで保護された埋め込みが疑われる場合は、通常、これが最も速い方法です。

### steghide

`JPEG, BMP, WAV, AU` に対応しており、暗号化されたペイロードを埋め込み・抽出できます。

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

PNG/BMP/GIF/WebP/WAVに対応しています。

Repo: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — ピンク、サンタの願い事、クリスマスのメタデータ、キャプチャされたノイズ](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
