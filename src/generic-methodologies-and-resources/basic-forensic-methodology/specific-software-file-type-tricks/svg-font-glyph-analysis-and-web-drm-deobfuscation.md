# SVG/Font Glyph Analysis と Web DRM Deobfuscation（Raster Hashing + SSIM）

{{#include ../../../banners/hacktricks-training.md}}

このページでは、位置情報付きの glyph run とリクエストごとの vector glyph 定義（SVG paths）を提供し、scraping を防ぐためにリクエストごとに glyph ID をランダム化する web reader から、テキストを復元する実践的な手法について説明します。基本的な考え方は、リクエスト単位の数値 glyph ID を無視し、Raster Hashing によって視覚的な形状を fingerprinting したうえで、reference font atlas に対する SSIM を使って形状を文字に対応付けることです。同様の保護機能を持つ viewer にも、このアプローチを応用できる場合があります。<sup>[[1]](#references)</sup>

警告：これらの技術は、正当に所有しているコンテンツのバックアップにのみ使用し、適用される法律および規約を遵守してください。

## Acquisition（例：Kindle Cloud Reader）

確認された Endpoint：<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

セッションごとに必要な材料：<sup>[[1]](#references)</sup>
- Browser session cookies（通常の Amazon login）
- startReading API call から取得した Rendering token
- renderer が使用する追加の ADP session token

動作：<sup>[[1]](#references)</sup>
- Browser と同等の headers および cookies を付けて各 request を送信すると、5ページに制限された TAR archive が返されます。
- 長い本の場合は多数の batch が必要になり、各 batch では異なるランダム化 glyph ID mapping が使用されます。

一般的な TAR の内容：<sup>[[1]](#references)</sup>
- page_data_0_4.json — glyph ID の sequence として格納された位置情報付き text run（Unicode ではない）
- glyphs.json — 各 glyph および fontFamily に対応するリクエストごとの SVG path 定義
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mapping

ページ run の構造例：<sup>[[1]](#references)</sup>
```json
{
"type": "TextRun",
"glyphs": [24, 25, 74, 123, 91],
"rect": {"left": 100, "top": 200, "right": 850, "bottom": 220},
"fontStyle": "italic",
"fontWeight": 700,
"fontSize": 12.5
}
```
glyphs.json エントリの例:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
アンチスクレイピングのパスに関する注意事項:<sup>[[1]](#references)</sup>
- パスには、ベクトルパーサーや単純なパスサンプリングを混乱させる微小な相対移動（例: `m3,1 m1,6 m-4,-7`）が含まれる場合があります。
- コマンドや座標の差分を計算するのではなく、堅牢な SVG engine（例: CairoSVG）を使用して、塗りつぶされた完全なパスを常に render してください。

## 単純な decoding が失敗する理由

- リクエストごとにランダム化された glyph 置換: glyph ID→character の mapping はバッチごとに変化し、ID にグローバルな意味はありません。<sup>[[1]](#references)</sup>
- SVG 座標の直接比較は脆弱です: 同一の形状でも、リクエストごとに数値座標やコマンド encoding が異なる場合があります。<sup>[[1]](#references)</sup>
- 分離された glyph に対する OCR の性能は低く（約50%）、句読点や類似した glyph を混同し、ligature も無視します。<sup>[[1]](#references)</sup>

## 実用的な pipeline: リクエストに依存しない glyph の正規化と mapping

1) リクエストごとの SVG glyph を rasterize する
- 提供された `path` を使って glyph ごとに最小限の SVG document を作成し、CairoSVG または複雑なパスシーケンスを処理できる同等の engine を使用して、固定 canvas（例: 512×512）に render します。<sup>[[1]](#references)[[2]](#references)</sup>
- 白地に黒で塗りつぶして render し、renderer や AA に依存する artifact を排除するため、stroke は避けます。

2) リクエスト間の identity 判定に perceptual hashing を使用する
- 各 glyph image の perceptual hash（例: `imagehash.phash` による pHash）を計算します。<sup>[[3]](#references)</sup>
- hash を stable ID として扱います: リクエスト間で同じ visual shape は同じ perceptual hash にまとめられ、ランダム化された ID を無効化できます。

3) reference font atlas の生成
- 対象の TTF/OTF fonts（例: Bookerly normal/italic/bold/bold-italic）を download します。<sup>[[1]](#references)</sup>
- A–Z、a–z、0–9、句読点、特殊記号（em/en dash、引用符）、および明示的な ligature: `ff`、`fi`、`fl`、`ffi`、`ffl` の候補を render します。
- font variant（normal/italic/bold/bold-italic）ごとに個別の atlas を保持します。
- ligature で glyph レベルの忠実度が必要な場合は、適切な text shaper（HarfBuzz）を使用します。Pillow ImageFont による単純な rasterization でも、ligature string を直接 render し、shaping engine がそれを解決すれば十分な場合があります。

4) SSIM による visual similarity matching
- 各 unknown glyph image について、すべての font variant atlas にあるすべての候補 image と SSIM（Structural Similarity Index）を計算します。<sup>[[4]](#references)</sup>
- 最も高い score の match に対応する character string を割り当てます。SSIM は、pixel-exact な比較よりも、antialiasing、scale、座標のわずかな違いを適切に吸収します。<sup>[[1]](#references)[[4]](#references)</sup>

5) edge の処理と再構成
- glyph が ligature（複数文字）に mapping された場合は、decoding 中に展開します。<sup>[[1]](#references)</sup>
- run rectangle（top/left/right/bottom）を使用して、段落区切り（Y の差分）、alignment（X の pattern）、style、size を推測します。<sup>[[1]](#references)</sup>
- `fontStyle`、`fontWeight`、`fontSize`、および internal link を保持したまま HTML/EPUB に serialize します。<sup>[[1]](#references)</sup>

### 実装のヒント

- hash と SSIM の前に、すべての image を同じ size と grayscale に normalize します。
- perceptual hash を key に cache し、バッチ間で繰り返される glyph の SSIM 再計算を避けます。
- 識別性能を高めるため、高品質な raster size（例: 256–512 px）を使用し、SSIM を高速化する必要があれば事前に downscale します。
- Pillow を使用して TTF 候補を render する場合は、同じ canvas size を設定して glyph を中央揃えにし、ascender/descender が切り取られないよう padding を追加します。

<details>
<summary>Python: end-to-end glyph normalization and matching (raster hash + SSIM)</summary>
```python
# pip install cairosvg pillow imagehash scikit-image uharfbuzz freetype-py
import io, json, tarfile, base64, math
from PIL import Image, ImageOps, ImageDraw, ImageFont
import imagehash
from skimage.metrics import structural_similarity as ssim
import cairosvg

CANVAS = (512, 512)
BGCOLOR = 255  # white
FGCOLOR = 0    # black

# --- SVG -> raster ---
def rasterize_svg_path(path_d: str, canvas=CANVAS) -> Image.Image:
# Build a minimal SVG document; rely on CAIRO for correct path handling
svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{canvas[0]}" height="{canvas[1]}" viewBox="0 0 2048 2048">
<rect width="100%" height="100%" fill="white"/>
<path d="{path_d}" fill="black" fill-rule="nonzero"/>
</svg>'''
png_bytes = cairosvg.svg2png(bytestring=svg.encode('utf-8'))
img = Image.open(io.BytesIO(png_bytes)).convert('L')
return img

# --- Perceptual hash ---
def phash_img(img: Image.Image) -> str:
# Normalize to grayscale and fixed size
img = ImageOps.grayscale(img).resize((128, 128), Image.LANCZOS)
return str(imagehash.phash(img))

# --- Reference atlas from TTF ---
def render_char(candidate: str, ttf_path: str, canvas=CANVAS, size=420) -> Image.Image:
# Render centered text on same canvas to approximate glyph shapes
font = ImageFont.truetype(ttf_path, size=size)
img = Image.new('L', canvas, color=BGCOLOR)
draw = ImageDraw.Draw(img)
w, h = draw.textbbox((0,0), candidate, font=font)[2:]
dx = (canvas[0]-w)//2
dy = (canvas[1]-h)//2
draw.text((dx, dy), candidate, fill=FGCOLOR, font=font)
return img

# --- Build atlases for variants ---
FONT_VARIANTS = {
'normal':   '/path/to/Bookerly-Regular.ttf',
'italic':   '/path/to/Bookerly-Italic.ttf',
'bold':     '/path/to/Bookerly-Bold.ttf',
'bolditalic':'/path/to/Bookerly-BoldItalic.ttf',
}
CANDIDATES = [
*[chr(c) for c in range(0x20, 0x7F)],  # basic ASCII
'–', '—', '“', '”', '‘', '’', '•',      # common punctuation
'ff','fi','fl','ffi','ffl'              # ligatures
]

def build_atlases():
atlases = {}  # variant -> list[(char, img)]
for variant, ttf in FONT_VARIANTS.items():
out = []
for ch in CANDIDATES:
img = render_char(ch, ttf)
out.append((ch, img))
atlases[variant] = out
return atlases

# --- SSIM match ---

def best_match(img: Image.Image, atlases) -> tuple[str, float, str]:
# Returns (char, score, variant)
img_n = ImageOps.grayscale(img).resize((128,128), Image.LANCZOS)
img_n = ImageOps.autocontrast(img_n)
best = ('', -1.0, '')
import numpy as np
candA = np.array(img_n)
for variant, entries in atlases.items():
for ch, ref in entries:
ref_n = ImageOps.grayscale(ref).resize((128,128), Image.LANCZOS)
ref_n = ImageOps.autocontrast(ref_n)
candB = np.array(ref_n)
score = ssim(candA, candB)
if score > best[1]:
best = (ch, score, variant)
return best

# --- Putting it together for one TAR batch ---

def process_tar(tar_path: str, cache: dict, atlases) -> list[dict]:
# cache: perceptual-hash -> mapping {char, score, variant}
out_runs = []
with tarfile.open(tar_path, 'r:*') as tf:
glyphs = json.load(tf.extractfile('glyphs.json'))
# page_data_0_4.json may differ in name; list members to find it
pd_name = next(m.name for m in tf.getmembers() if m.name.startswith('page_data_'))
page_data = json.load(tf.extractfile(pd_name))

# 1. Rasterize + hash all glyphs for this batch
id2hash = {}
for gid, meta in glyphs.items():
img = rasterize_svg_path(meta['path'])
h = phash_img(img)
id2hash[int(gid)] = (h, img)

# 2. Ensure all hashes are resolved to characters in cache
for h, img in {v[0]: v[1] for v in id2hash.values()}.items():
if h not in cache:
ch, score, variant = best_match(img, atlases)
cache[h] = { 'char': ch, 'score': float(score), 'variant': variant }

# 3. Decode text runs
for run in page_data:
if run.get('type') != 'TextRun':
continue
decoded = []
for gid in run['glyphs']:
h, _ = id2hash[gid]
decoded.append(cache[h]['char'])
run_out = {
'text': ''.join(decoded),
'rect': run.get('rect'),
'fontStyle': run.get('fontStyle'),
'fontWeight': run.get('fontWeight'),
'fontSize': run.get('fontSize'),
}
out_runs.append(run_out)
return out_runs

# Usage sketch:
# atlases = build_atlases()
# cache = {}
# for tar in sorted(glob('batches/*.tar')):
#     runs = process_tar(tar, cache, atlases)
#     # accumulate runs for layout reconstruction → EPUB/HTML
```
</details>

## Layout/EPUB 再構築のヒューリスティクス

元のレポートでは、再構築したドキュメントの formatting を保持するために、run の geometry、style fields、link metadata を使用していました。<sup>[[1]](#references)</sup>

- Paragraph breaks: 次の run の上端 Y が、前の行の baseline を font size に対する threshold 分だけ超えた場合、新しい paragraph を開始します。<sup>[[1]](#references)</sup>
- Alignment: left-aligned paragraph は類似した左 X 座標でグループ化し、centered line は左右の margin の対称性で検出し、right-aligned は右端で検出します。
- Styling: `fontStyle`/`fontWeight` によって italic/bold を保持し、`fontSize` の bucket ごとに CSS class を変えて heading と body を近似します。
- Links: run に link metadata（例: `positionId`）が含まれている場合、anchor と internal href を出力します。

## SVG anti-scraping path tricks の軽減

- `fill-rule: nonzero` を使用した filled path と適切な renderer（CairoSVG、resvg）を使用します。path token normalization に依存しないでください。<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- stroke rendering を避け、micro relative move による hairline artifact を回避するため、filled solid に集中します。
- batch 間で同一の shape が一貫して rasterize されるよう、render ごとに安定した viewBox を維持します。

## Performance notes

- 実際には、books は数百個の unique glyph（ligature を含めて約361個など）に収束します。perceptual hash ごとに SSIM result を cache します。<sup>[[1]](#references)</sup>
- 初回の discovery 後は、後続の batch で既知の hash が主に再利用されるため、decoding は I/O-bound になります。
- 引用されたレポートでは、平均 SSIM は約0.95でした。score の低い match は manual review 用に flag します。<sup>[[1]](#references)</sup>

## 他の viewer への generalization

Kindle workflow は、次の条件を満たす類似 viewer が同じ normalization に対応できる可能性を示しています。<sup>[[1]](#references)</sup>
- request-scoped numeric ID を持つ positioned glyph run を返す
- request ごとの vector glyph（SVG path または subset font）を提供する
- request ごとの page 数を制限する

…これらは同じ normalization で処理できます。
- request ごとの shape を rasterize → perceptual hash → shape ID
- font variant ごとの candidate glyph/ligature の Atlas
- SSIM（または類似の perceptual metric）で character を割り当てる
- run rectangle/style から layout を再構築する

## 最小 acquisition の例（sketch）

browser の DevTools を使用して、reader が `/renderer/render` を request するときに使用する正確な header、cookie、token を capture します。その後、script または curl からそれらを replicate します。<sup>[[1]](#references)</sup> Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
パラメータ（book ASIN、page window、viewport）を読者のリクエストに合わせて調整します。1リクエストあたり最大5ページまでです。<sup>[[1]](#references)</sup>

## 達成可能な結果

- perceptual hashing により、100以上のランダム化されたアルファベットを単一の glyph space に集約できます。<sup>[[1]](#references)</sup>
- 引用された920ページのテストでは、361個の固有 glyph が平均 SSIM 0.9527で100%マッチしました。<sup>[[1]](#references)</sup>
- 元のレポートでは、再構築されたEPUBは元のものとほぼ見分けがつかないと説明されています。<sup>[[1]](#references)</sup>

## References

- [1] [AmazonのKindle Web Obfuscationを逆解析した話 ― アプリがひどかったので (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG ― SVGからPNGへのrenderer](https://cairosvg.org/)
- [3] [imagehash ― perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image ― Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 ― Fill properties](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg ― SVG rendering library](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
