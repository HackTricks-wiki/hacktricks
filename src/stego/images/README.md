# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

CTFの画像stegoは、ほとんどの場合、次のいずれかに分類されます。

- LSB/bit-planes（PNG/BMP）
- Metadata/comment payloads
- PNG chunkの異常 / 破損の修復
- JPEG DCT-domain tools（OutGuessなど）
- Frame-based（GIF/APNG）

## 初期調査

詳細なコンテンツ分析の前に、コンテナレベルの痕跡を優先して調べます。ファイルの識別やcarvingについては、画像固有のテストを行う前に[一般的なstegoワークフロー](../workflow/)を参照してください。

- ファイルを検証し、構造を調べます: `file`、`magick identify -verbose`、フォーマット検証ツール（例: `pngcheck`）。
- Metadataと可視文字列を抽出します: `exiftool -a -u -g1`、`strings`。
- 埋め込み/追加コンテンツを確認します: `binwalk`とファイル末尾の調査（`tail | xxd`）。
- コンテナに応じて調査方法を切り替えます:
  - PNG/BMP: bit-planes/LSBとchunkレベルの異常。
  - JPEG: metadata + DCT-domain tooling（OutGuess/F5系）。
  - GIF/APNG: フレーム抽出、フレーム差分、palette tricks。

## Bit-planes / LSB

### Technique

PNG/BMPは、**bit-level manipulation**が容易な方法でピクセルを保存するため、CTFでよく使われます。典型的な隠蔽/抽出の仕組みは次のとおりです。

- 各ピクセルのチャンネル（R/G/B/A）には複数のビットがあります。
- 各チャンネルの**least significant bit**（LSB）を変更しても、画像はほとんど変わりません。
- 攻撃者はこれらの下位ビットにデータを隠します。stride、permutation、チャンネルごとの選択を使う場合もあります。

チャレンジで想定されるもの:

- payloadが1つのチャンネルだけにある（例: `R` LSB）。
- payloadがalpha channelにある。
- 抽出後にpayloadが圧縮/エンコードされている。
- メッセージが複数のplaneに分散されているか、plane間のXORで隠されている。

遭遇する可能性があるその他の手法（実装に依存）:

- **LSB matching**（ビットを反転するだけでなく、目標ビットに合わせて+/-1の調整を行う）
- **Palette/index-based hiding**（indexed PNG/GIFで、raw RGBではなくcolor indicesにpayloadを隠す）
- **Alpha-only payloads**（RGB表示では完全に見えない）

### Indexed-color palette indices

Indexed PNGやGIFは、ピクセルごとにRGB tripletではなくpalette **index**を保存します。2つのindexが同じ可視色に対応することがあるため、分析前にRGBへ変換すると、隠された違いが失われる場合があります。重複または類似したpalette entryを調べ、疑わしい各indexを使うピクセルのbinary maskを作成してください。最近のGIFチャレンジでは、これによって隠されたテキストやQRコードの変化が見つかっています。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

単一フレームのindexed PNG（またはGIFの**最初のフレーム**）では、Pillowの`P` modeを維持し、スクリプトで報告された興味深いindexに`target`を変更してください。indexを選ぶ際は、RGBだけでなく透明度（`tRNS`またはGIFのtransparency index）も確認してください。<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

アニメーション GIF の場合は、各フレームを個別に調べます。Pillow は通常、後続フレームを合成する際に RGB/RGBA に変換します。`GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` を設定すると、パレットが変化しない間は `P` モードが維持されます。フレームにローカルパレットがある場合や、すでに合成済みの場合は、RGB に変換されたピクセルをインデックスとして扱わず、元のインデックス付きフレームデータを調べてください。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### ツール

#### zsteg

`zsteg` は、PNG/BMP の LSB/ビットプレーン抽出パターンを多数列挙します:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: メタデータ、画像変換、LSBの各種パターンの総当たりなど、一連の変換を実行します。
- `stegsolve`: 手動で視覚フィルターを適用します（チャンネルの分離、プレーンの検査、XORなど）。

Stegsolveのダウンロード: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFTベースの可視化テクニック

FFTはLSB抽出ではありません。周波数空間に意図的に隠されたコンテンツや、目立たないパターンを扱うためのものです。

- EPFLのデモ: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTFでよく使われるWebベースのトリアージツール:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNGの内部構造: チャンク、破損、隠しデータ

### テクニック

PNGはチャンク形式です。多くのチャレンジでは、ペイロードはピクセル値ではなく、コンテナ／チャンクレベルに保存されています。

- **`IEND`以降の余分なバイト**（多くのビューアは末尾のバイトを無視します）
- **ペイロードを含む非標準の補助チャンク**。[PNGチャンクの走査とカービングのワークフロー](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads)を参照してください。
- **破損したヘッダー**。寸法を隠したり、修復するまでパーサーを機能不全にしたりします。

優先して確認するチャンクの場所:

- `tEXt` / `iTXt` / `zTXt`（テキストメタデータ。圧縮されている場合もあります）
- `iCCP`（ICCプロファイル）や、ペイロードの格納に使われるその他の補助チャンク
- `eXIf`（PNG内のEXIFデータ）

### PNGスキャンラインのフィルターバイトを格納領域として使う

PNGでは、展開後の`IDAT`ストリーム内で、各スキャンラインの前にフィルタータイプを示す1バイト（0～4）が格納されます。このバイトはピクセル値ではありません。デコードされたRGBピクセルには元のフィルター選択は保持されず、再エンコードによって変わることもあります。エンコーダーがフィルターを正当に変えることもありますが、意図的なパターンを使って短いメッセージをエンコードできます。最近のチャレンジでは、フィルター値1～4が2ビットのシンボルとして使われていました。**元のファイル**を調べ、展開する前にすべての`IDAT`データを連結してください。以下に示す、インターレースなしの8ビットRGB/RGBAの場合、ストライドは幅×チャンネル数です。Adam7画像では、パスごとのスキャンライン幅が必要です。<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>再エンコードせずにPNGスキャンラインのフィルターバイトを一覧表示する</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

`python3 filters.py suspect.png` として実行します。デコードされたピクセルではなく、フィルターのシーケンスがもっともらしいシンボルマッピングに従っているか確認します。マッピングの選択はチャレンジごとに異なります。変化があるだけでは、ステガノグラフィの証拠にはなりません。<sup>[[3]](#references)[[7]](#references)</sup>

### トリアージ用コマンド

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

確認する点:

- 幅/高さ/ビット深度/色タイプの不自然な組み合わせ
- CRC/チャンクのエラー（pngcheckは通常、正確なオフセットを示します）
- `IEND` の後に追加データがあるという警告

チャンクをさらに詳しく確認する場合:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

有用な参考資料:

- PNG仕様（構造、チャンク）: https://www.w3.org/TR/PNG/
- ファイル形式のテクニック（PNG/JPEG/GIFの特殊ケース）: https://github.com/corkami/docs

## JPEG: メタデータ、DCT-domainツール、ELAの限界

### 技法

JPEGは生のピクセルとして保存されるのではなく、DCT domainで圧縮されます。そのため、JPEG stegoツールはPNG LSBツールとは異なります。

- メタデータやコメントのペイロードはファイルレベルにあり、シグナルが強く、すばやく調査できる
- DCT-domain stegoツールは、周波数係数にビットを埋め込む

実際の運用では、JPEGを次のように扱います。

- メタデータセグメントのコンテナ（シグナルが強く、すばやく調査できる）
- 専用のstegoツールが処理する圧縮信号領域（DCT係数）

### クイックチェック

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

高シグナルな場所:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF、`APPn` for vendor data)

### 一般的なツール

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG内のsteghide payloadsに特に対応している場合は、`stegseek`の使用を検討してください（古いスクリプトよりbruteforceが高速です）:

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELAは異なる再圧縮アーティファクトを強調表示します。編集された領域を示す手がかりになりますが、それ自体はstego detectorではありません:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## アニメーション画像

### 手法

アニメーション画像では、メッセージが次のいずれかに含まれていると想定してください:

- 単一のフレーム（簡単）、または
- 複数のフレームに分散（順序が重要）、または
- 連続するフレームをdiffした場合にのみ見える

### フレームの抽出

```bash
ffmpeg -i anim.gif frame_%04d.png
```

その後、フレームを通常の PNG と同様に扱います: `zsteg`、`pngcheck`、チャンネル分離。

代替ツール:

- `gifsicle --explode anim.gif` (高速なフレーム抽出)
- `imagemagick`/`magick` によるフレームごとの変換

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

アニメーション形式のチャレンジでは、各フレーム内の特定の色の数が各バイトを表す場合があります。数を連結すると、メッセージを復元できます。<sup>[[1]](#references)</sup>

## Password-protected embedding

パスフレーズで保護された埋め込みであり、ピクセルレベルの操作ではないと考えられる場合、通常はこれが最も手早い方法です。

### steghide

`JPEG, BMP, WAV, AU` に対応し、暗号化されたペイロードを埋め込み・抽出できます。

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

リポジトリ: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

サポート対象: PNG/BMP/GIF/WebP/WAV。

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — ピンク、サンタのウィッシュリスト、クリスマスのメタデータ、Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 write-up — ねじれた色](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Portable Network Graphics (PNG)仕様、第3版](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — 水の底深くに何かがある](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow画像ファイル形式 — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a仕様](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF write-up](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
