# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

このページでは、位置情報付きの glyph run と、リクエストごとの vector glyph 定義（SVG paths）を提供し、さらに scraping を防ぐためにリクエストごとに glyph ID をランダム化する web reader から、テキストを復元する実践的な手法について説明します。基本的な考え方は、リクエスト単位の数値 glyph ID を無視し、raster hashing によって視覚的な形状を fingerprint し、その後、reference font atlas に対する SSIM を使って形状を文字にマッピングすることです。同様の保護機能を持つ viewer にも、この手法を応用できる可能性があります。<sup>[[1]](#references)</sup>

警告: これらの手法は、合法的に所有しているコンテンツのバックアップ、および適用される法律や利用規約の遵守のためにのみ使用してください。

## Acquisition (example: Kindle Cloud Reader)

確認された Endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

セッションごとに必要な materials:<sup>[[1]](#references)</sup>
- Browser session cookies（通常の Amazon login）
- startReading API call から取得した Rendering token
- renderer が使用する追加の ADP session token

動作:<sup>[[1]](#references)</sup>
- browser と同等の headers および cookies を付けて各 request を送信すると、最大 5 ページに制限された TAR archive が返されます。
- 長い book では多数の batch が必要になります。各 batch では異なるランダム化された glyph ID の mapping が使用されます。

一般的な TAR の contents:<sup>[[1]](#references)</sup>
- page_data_0_4.json — glyph ID の sequence として表現された位置情報付き text run（Unicode ではない）
- glyphs.json — 各 glyph および fontFamily に対する request ごとの SVG path 定義
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mappings

Example page run structure:<sup>[[1]](#references)</sup>
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
glyphs.json のエントリ例:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
アンチスクレイピングのパスに関する注意事項:<sup>[[1]](#references)</sup>
- パスには、多くのベクターパーサーや単純なパスサンプリングを混乱させる微小な相対移動（例: `m3,1 m1,6 m-4,-7`）が含まれる場合があります。
- コマンドや座標の差分を取るのではなく、必ず堅牢な SVG engine（例: CairoSVG）を使用して、塗りつぶされた完全なパスをレンダリングしてください。

## 単純なデコードが失敗する理由

- リクエストごとにランダム化された glyph の置換: glyph ID→character の mapping はバッチごとに変化するため、ID にグローバルな意味はありません。<sup>[[1]](#references)</sup>
- SVG 座標の直接比較は脆弱です: 同一の形状でも、リクエストごとに数値座標やコマンドのエンコーディングが異なる場合があります。<sup>[[1]](#references)</sup>
- 分離した glyph に対する OCR の性能は低く（約50%）、句読点や似た形の glyph を取り違え、ligature も無視します。<sup>[[1]](#references)</sup>

## 実用的な pipeline: リクエストに依存しない glyph の正規化と mapping

1) リクエストごとの SVG glyph を rasterize する
- 提供された `path` を使って glyph ごとに最小限の SVG document を構築し、CairoSVG または扱いの難しいパスシーケンスに対応した同等の engine を使用して、固定 canvas（例: 512×512）に render します。<sup>[[1]](#references)[[2]](#references)</sup>
- 白背景に黒で塗りつぶして render し、renderer や AA に依存するアーティファクトを排除するため、stroke は使用しないでください。

2) リクエスト間の同一性を perceptual hashing で判定する
- 各 glyph image の perceptual hash（例: `imagehash.phash` による pHash）を計算します。<sup>[[3]](#references)</sup>
- hash を stable ID として扱います: リクエスト間で同じ視覚形状は同じ perceptual hash に集約され、ランダム化された ID を無効化できます。

3) Reference font atlas の生成
- 対象の TTF/OTF font（例: Bookerly の normal/italic/bold/bold-italic）を download します。<sup>[[1]](#references)</sup>
- A–Z、a–z、0–9、句読点、特殊記号（em/en dash、引用符）、および明示的な ligature: `ff`、`fi`、`fl`、`ffi`、`ffl` の候補を render します。
- font variant（normal/italic/bold/bold-italic）ごとに別々の atlas を保持します。
- ligature で glyph-level の忠実度が必要な場合は、適切な text shaper（HarfBuzz）を使用してください。ligature 文字列を直接 render し、shaping engine が解決できる場合は、Pillow ImageFont による単純な rasterization でも十分です。

4) SSIM による visual similarity matching
- 各 unknown glyph image について、すべての font variant atlas にある全候補画像との SSIM（Structural Similarity Index）を計算します。<sup>[[4]](#references)</sup>
- 最も高いスコアの match に対応する character string を割り当てます。SSIM は、pixel-exact な比較よりも、アンチエイリアス、scale、座標の小さな違いを適切に吸収します。<sup>[[1]](#references)[[4]](#references)</sup>

5) エッジ処理と再構築
- glyph が ligature（複数文字）に mapping された場合は、decoding 中に展開します。<sup>[[1]](#references)</sup>
- run rectangle（top/left/right/bottom）を使用して、段落区切り（Y の差分）、alignment（X のパターン）、style、size を推測します。<sup>[[1]](#references)</sup>
- `fontStyle`、`fontWeight`、`fontSize`、および internal link を保持したまま、HTML/EPUB に serialize します。<sup>[[1]](#references)</sup>

### 実装のヒント

- hash と SSIM の前に、すべての image を同じ size の grayscale に normalize します。
- バッチ間で繰り返される glyph の SSIM 再計算を避けるため、perceptual hash ごとに cache します。
- 識別性能を高めるため、高品質な raster size（例: 256–512 px）を使用し、SSIM を高速化する必要がある場合は事前に downscale します。
- Pillow で TTF 候補を render する場合は、同じ canvas size を設定して glyph を中央揃えにし、ascender/descender が切れないように padding を追加します。

<details>
<summary>Python: glyph の end-to-end 正規化と matching（raster hash + SSIM）</summary>
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

元の report では、再構築された document の formatting を保持するために、run の geometry、style fields、link metadata が使用されていました。<sup>[[1]](#references)</sup>

- Paragraph breaks: 次の run の top Y が、前の行の baseline を（font size に対する threshold 分）超えた場合、新しい paragraph を開始します。<sup>[[1]](#references)</sup>
- Alignment: left-aligned paragraphs は類似した left X ごとにグループ化し、centered lines は左右の margin の対称性によって検出し、right-aligned は右端によって検出します。
- Styling: `fontStyle`/`fontWeight` によって italic/bold を保持し、`fontSize` の bucket ごとに CSS classes を変えて headings と body を近似します。
- Links: run に link metadata（例：`positionId`）が含まれている場合、anchors と internal hrefs を出力します。

## SVG anti-scraping path tricks の軽減

- `fill-rule: nonzero` を指定した filled paths と適切な renderer（CairoSVG、resvg）を使用します。path token normalization に依存しないでください。<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- stroke rendering を避け、micro relative moves によって生じる hairline artifacts を回避するため、filled solids に集中します。
- render ごとに安定した viewBox を維持し、同一の shapes が batches 間で一貫して rasterize されるようにします。

## Performance notes

- 実際には、books は数百個の unique glyphs（ligatures を含めて約361個など）に収束します。perceptual hash によって SSIM results を cache します。<sup>[[1]](#references)</sup>
- 初回の discovery 後は、後続の batches で既知の hashes が主に再利用され、decoding は I/O-bound になります。
- d report では、平均 SSIM は約 0.95 でした。score の低い matches には manual review のフラグを付けます。<sup>[[1]](#references)</sup>

## Generalization to other viewers

Kindle workflow は、次の条件を満たす類似の viewers が同じ normalization に適用できる可能性を示しています。<sup>[[1]](#references)</sup>
- request-scoped numeric IDs を持つ positioned glyph runs を返す
- per-request vector glyphs（SVG paths または subset fonts）を提供する
- request ごとの pages 数に上限を設ける

…次の同じ normalization で処理できます。
- per-request shapes を rasterize → perceptual hash → shape ID
- font variant ごとの candidate glyphs/ligatures の Atlas
- SSIM（または類似の perceptual metric）による characters の割り当て
- run rectangles/styles からの layout の再構築

## Minimal acquisition example (sketch)

browser の DevTools を使用して、reader が `/renderer/render` をリクエストする際に使用する正確な headers、cookies、tokens を capture します。その後、script または curl からそれらを replicate します。<sup>[[1]](#references)</sup> Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
パラメータ化（book ASIN、ページウィンドウ、viewport）を読者のリクエストに合わせて調整します。1回のリクエストにつき最大5ページまでです。<sup>[[1]](#references)</sup>

## 達成可能な結果

- perceptual hashing により、100以上のランダム化された alphabet を1つの glyph space に集約します。<sup>[[1]](#references)</sup>
- 920ページのテストでは、361個の固有 glyph が平均 SSIM 0.9527で100%マッチしました。<sup>[[1]](#references)</sup>
- 元のレポートでは、再構築された EPUB はオリジナルとほぼ見分けがつかないと説明されています。<sup>[[1]](#references)</sup>

## References

- [1] [Amazon の Kindle Web Obfuscation を逆解析した理由：アプリがひどかったから（Pixelmelt）](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVGからPNGへのレンダラー](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing（pHash）](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index（SSIM）](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill properties](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVGレンダリングライブラリ](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
