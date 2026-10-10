# 画像ステガノグラフィ

{{#include ../../banners/hacktricks-training.md}}

多くのCTF画像ste goは、次のいずれかに分類されます。

- LSB/bit-planes（PNG/BMP）
- メタデータ/comment payloads
- PNG chunkの異常/破損の修復
- JPEG DCT-domain tools（OutGuessなど）
- フレームベース（GIF/APNG）

## 初期トリアージ

詳細な内容分析に進む前に、まずコンテナレベルの証拠を優先して確認します。

- ファイルを検証して構造を調べます。`file`、`magick identify -verbose`、形式検証ツール（例：`pngcheck`）を使います。
- メタデータと可視文字列を抽出します。`exiftool -a -u -g1`、`strings`を使います。
- 埋め込み/追記コンテンツを確認します。`binwalk`とファイル末尾の確認（`tail | xxd`）を使います。
- コンテナに応じて調査方法を分けます。
  - PNG/BMP：bit-planes/LSBとchunkレベルの異常
  - JPEG：メタデータとDCT-domain tooling（OutGuess/F5系）
  - GIF/APNG：フレーム抽出、フレーム差分、palette tricks

## Bit-planes / LSB

### Technique

PNG/BMPは、ピクセルをbit-level manipulationしやすい形式で保存するため、CTFでよく使われます。典型的な隠蔽/抽出の仕組みは次のとおりです。

- 各ピクセルのチャンネル（R/G/B/A）には、複数のビットがあります。
- 各チャンネルの**最下位ビット**（LSB）を変更しても、画像への影響はごくわずかです。
- 攻撃者はこれらの下位ビットにデータを隠します。stride、permutation、チャンネルごとの選択が使われることもあります。

チャレンジで想定されるもの：

- payloadが1つのチャンネル（例：`R`のLSB）だけにある。
- payloadがalpha channelにある。
- 抽出後にpayloadが圧縮/エンコードされている。
- メッセージが複数のplaneに分散されている、またはplane間のXORで隠されている。

遭遇する可能性のあるその他の手法（実装によって異なります）：

- **LSB matching**（ビットを反転するだけでなく、目標ビットに合わせて値を±1調整する）
- **Palette/index-based hiding**（indexed PNG/GIFで、raw RGBではなくcolor indicesにpayloadを隠す）
- **Alpha-only payloads**（RGB viewでは完全に見えない）

### Tooling

#### zsteg

`zsteg`は、PNG/BMP向けに多数のLSB/bit-plane抽出パターンを列挙します。

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 一連の変換を実行する（メタデータ、画像変換、LSBの各種パターンの総当たり）。
- `stegsolve`: 手動で視覚的なフィルターを適用する（チャンネル分離、プレーン検査、XORなど）。

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFTはLSB抽出ではなく、コンテンツが周波数領域に意図的に隠されている場合や、微妙なパターンを見つけるために使います。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTFでよく使われるWebベースのトリアージツール:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNGの内部構造: チャンク、破損、隠しデータ

### Technique

PNGはチャンク形式です。多くのチャレンジでは、ペイロードはピクセル値ではなく、コンテナ／チャンクのレベルに格納されています。

- **`IEND`の後の余分なバイト**（多くのビューアは末尾のバイトを無視する）
- **ペイロードを含む非標準の補助チャンク**
- **寸法を隠したり、修正するまでパーサーを停止させたりする破損したヘッダー**

重点的に確認するチャンク:

- `tEXt` / `iTXt` / `zTXt`（テキストメタデータ。圧縮されている場合もある）
- `iCCP`（ICCプロファイル）や、データの格納に使われるその他の補助チャンク
- `eXIf`（PNG内のEXIFデータ）

### Triage commands

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

確認すべき点：

- 幅/高さ/ビット深度/色タイプの不自然な組み合わせ
- CRC/chunk エラー（pngcheck は通常、正確なオフセットを示します）
- `IEND` の後に追加データがあるという警告

chunk の詳細を確認する場合：

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

参考資料:

- PNG仕様（構造、チャンク）: https://www.w3.org/TR/PNG/
- ファイル形式のテクニック（PNG/JPEG/GIFの特殊なケース）: https://github.com/corkami/docs

## JPEG: メタデータ、DCT-domainツール、ELAの限界

### 手法

JPEGは生のピクセルとして保存されるのではなく、DCT domainで圧縮されます。そのため、JPEGのstegoツールはPNG LSBツールとは異なります。

- メタデータやコメントのペイロードはファイルレベルにあり（high-signalで、すばやく調査できる）
- DCT-domainのstegoツールは周波数係数にビットを埋め込む

実運用では、JPEGを次のように扱います。

- メタデータセグメントを格納するコンテナ（high-signalで、すばやく調査できる）
- 専用のstegoツールが動作する圧縮信号領域（DCT係数）

### すばやく確認する方法

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

高シグナルな場所:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments（EXIF用の`APP1`、ベンダーデータ用の`APPn`）

### 一般的なツール

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG内のsteghide payloadを特に調査している場合は、`stegseek`の使用を検討してください（古いスクリプトよりbruteforceが高速）:

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELAは再圧縮によるアーティファクトの違いを強調します。編集された領域の特定に役立ちますが、それ自体はstego検出ツールではありません:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## アニメーション画像

### 手法

アニメーション画像では、メッセージが次のいずれかにあると想定します:

- 単一フレーム内（簡単）
- 複数のフレームに分散（順序が重要）
- 連続するフレームの差分を取ったときにのみ表示される

### フレームの抽出

```bash
ffmpeg -i anim.gif frame_%04d.png
```

次に、フレームを通常のPNGとして扱います: `zsteg`、`pngcheck`、チャンネル分離。

代替ツール:

- `gifsicle --explode anim.gif` (高速なフレーム抽出)
- `imagemagick`/`magick` によるフレームごとの変換

フレーム差分の比較が決め手になることもよくあります:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNGピクセル数エンコーディング

- APNGコンテナを検出する: `exiftool -a -G1 file.png | grep -i animation` または `file`。
- タイミングを変更せずにフレームを抽出する: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- フレームごとのピクセル数としてエンコードされたpayloadを復元する:

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

アニメーション形式の challenge では、各フレーム内の特定の色の数を各バイトとして符号化している場合があります。各フレームの数を連結すると、メッセージを復元できます。<sup>[[1]](#references)</sup>

## パスワード保護された埋め込み

pixel-level manipulation ではなく passphrase で保護された embedding が疑われる場合、通常はこれが最も手早い方法です。

### steghide

`JPEG, BMP, WAV, AU` に対応し、暗号化された payload を埋め込み・抽出できます。

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

PNG/BMP/GIF/WebP/WAVに対応しています。

Repo: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — pink、サンタのウィッシュリスト、クリスマスのメタデータ、キャプチャされたノイズ](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
