# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

このページでは、位置指定された glyph run とリクエストごとの vector glyph 定義（SVG paths）を提供し、スクレイピングを防ぐためにリクエストごとに glyph ID をランダム化する web reader から、テキストを復元する実践的な techniques について説明します。基本的な考え方は、リクエスト単位の数値 glyph ID を無視し、raster hashing によって視覚的な形状の fingerprint を作成し、その後、reference font atlas に対する SSIM を使って形状を文字にマッピングすることです。この workflow は Kindle Cloud Reader に限らず、同様の保護機能を持つあらゆる viewer に応用できます。<sup>[[1]](#references)</sup>

警告: これらの techniques は、自分が合法的に所有する content の backup を作成する目的でのみ使用し、適用される法律および terms を遵守してください。

## Acquisition (example: Kindle Cloud Reader)

観測された endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

セッションごとに必要な materials:
- Browser session cookies（通常の Amazon login）
- startReading API call から取得した rendering token
- renderer が使用する追加の ADP session token

動作:
- Browser と同等の headers および cookies を付けて各 request を送信すると、5 pages に制限された TAR archive が返されます。
- 長い book の場合は多数の batches が必要になり、各 batch では異なるランダム化された glyph ID の mapping が使用されます。

一般的な TAR の contents:
- page_data_0_4.json — glyph ID の sequences として表現された、位置指定された text runs（Unicode ではない）
- glyphs.json — 各 glyph および fontFamily に対する、リクエストごとの SVG path definitions
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mappings

Example page run structure:
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
glyphs.json のエントリ例:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
アンチスクレイピング用のパス trick に関する注意:
- パスには、多くの vector parser や naïve なパスサンプリングを混乱させる micro relative move（例: `m3,1 m1,6 m-4,-7`）が含まれる場合があります。
- コマンドや座標の差分を取るのではなく、堅牢な SVG engine（例: CairoSVG）で、塗りつぶした完全なパスを必ず render してください。

## naïve な decoding が失敗する理由

- リクエストごとに glyph の置換がランダム化される: glyph ID→character の mapping は batch ごとに変わるため、ID に global な意味はありません。<sup>[[1]](#references)</sup>
- SVG 座標の直接比較は脆弱です: 同一の shape でも、リクエストごとに数値座標や command encoding が異なる場合があります。
- 分離した glyph に対する OCR の性能は低く（約50%）、句読点や look-alike glyph を取り違え、ligature も無視します。

## Working pipeline: request-agnostic な glyph の normalization と mapping

1) リクエストごとの SVG glyph を rasterize する
- 提供された `path` を使って glyph ごとに最小限の SVG document を作成し、CairoSVG または tricky な path sequence を処理できる同等の engine で、固定 canvas（例: 512×512）に render します。<sup>[[1]](#references)[[2]](#references)</sup>
- 白地に黒の塗りつぶしとして render し、renderer や AA に依存する artifact を排除するため、stroke は使用しません。

2) リクエスト間の identity を perceptual hashing で判定する
- 各 glyph image の perceptual hash（例: `imagehash.phash` による pHash）を計算します。<sup>[[3]](#references)</sup>
- hash を stable ID として扱います。リクエスト間で同じ visual shape は同じ perceptual hash に集約されるため、randomized ID を無効化できます。

3) Reference font atlas の生成
- 対象の TTF/OTF font（例: Bookerly normal/italic/bold/bold-italic）を download します。
- A–Z、a–z、0–9、句読点、special mark（em/en dash、quote）、および明示的な ligature: `ff`、`fi`、`fl`、`ffi`、`ffl` の候補を render します。
- font variant（normal/italic/bold/bold-italic）ごとに個別の atlas を保持します。
- ligature で glyph-level の fidelity が必要な場合は、proper text shaper（HarfBuzz）を使用します。ligature string を直接 render し、shaping engine が解決できる場合は、Pillow ImageFont による単純な rasterization でも十分です。

4) SSIM による visual similarity matching
- 各 unknown glyph image について、すべての font variant atlas にあるすべての candidate image と SSIM（Structural Similarity Index）を計算します。<sup>[[4]](#references)</sup>
- 最も高い score の match に対応する character string を割り当てます。SSIM は pixel-exact な比較よりも、小さな antialiasing、scale、座標の差異を適切に吸収します。

5) Edge の処理と reconstruction
- glyph が ligature（複数文字）に mapping された場合は、decoding 中に展開します。
- run rectangle（top/left/right/bottom）を使用して、paragraph break（Y delta）、alignment（X pattern）、style、size を推測します。
- `fontStyle`、`fontWeight`、`fontSize`、および internal link を保持したまま HTML/EPUB に serialize します。

### Implementation tips

- hash と SSIM の前に、すべての image を同じ size と grayscale に normalize します。
- perceptual hash ごとに cache し、batch 間で繰り返される glyph の SSIM 再計算を避けます。
- より優れた discrimination のために高品質な raster size（例: 256–512 px）を使用し、SSIM を高速化する必要に応じて downscale します。
- Pillow で TTF candidate を render する場合は、同じ canvas size を設定して glyph を中央揃えにし、ascender/descender が clipping されないよう padding を追加します。

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

## Layout/EPUB 再構築のヒューリスティック

- Paragraph breaks: 次の run の top Y が、前の行のベースラインをフォントサイズに対するしきい値以上に超えた場合、新しい段落を開始します。<sup>[[1]](#references)</sup>
- Alignment: 左揃えの段落は、類似した左 X に基づいてグループ化します。左右の余白が対称的な行を中央揃えとして検出し、右端に基づいて右揃えを検出します。
- Styling: `fontStyle`/`fontWeight` により italic/bold を保持し、`fontSize` のバケットごとに CSS クラスを変えて、見出しと本文を近似します。
- Links: run に link metadata（例: `positionId`）が含まれる場合、anchors と内部 hrefs を出力します。

## SVG anti-scraping path tricks の軽減

- `fill-rule: nonzero` を使用した filled paths と、適切な renderer（CairoSVG、resvg）を使用します。path token normalization に依存しないでください。<sup>[[1]](#references)</sup>
- stroke rendering を避け、micro relative moves によって生じる hairline artifacts を回避するため、filled solids に集中します。
- バッチ間で同一の shape が一貫して rasterize されるよう、render ごとに安定した viewBox を維持します。

## Performance notes

- 実際には、books は数百個の unique glyphs（ligatures を含めて約361個など）に収束します。perceptual hash により SSIM の結果を cache します。<sup>[[1]](#references)</sup>
- 初期 discovery 後の future batches では、既知の hashes が主に再利用されるため、decoding は I/O-bound になります。
- Average SSIM ≈0.95 は強い signal です。低スコアの matches には manual review 用の flag を付けることを検討してください。

## 他の viewers への一般化

次の条件を満たす Any system は:<sup>[[1]](#references)</sup>
- request-scoped numeric IDs を持つ positioned glyph runs を返す
- per-request vector glyphs（SVG paths または subset fonts）を送信する
- bulk export を防ぐため、request ごとの pages 数に上限を設ける

…同じ normalization で処理できます:
- per-request shapes を rasterize → perceptual hash → shape ID
- font variant ごとの candidate glyphs/ligatures の Atlas
- SSIM（または類似の perceptual metric）で characters を割り当てる
- run rectangles/styles から layout を再構築する

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
パラメータ化（book ASIN、page window、viewport）を読者のリクエストに合わせて調整します。1リクエストあたり最大5ページまでとします。

## 達成可能な結果

- perceptual hashing<sup>[[1]](#references)</sup> により、100以上のランダム化されたアルファベットを単一の glyph space に統合
- atlases に ligatures と variants が含まれる場合、平均 SSIM 約0.95で unique glyphs を100%マッピング
- 元のものと視覚的に区別できない EPUB/HTML を再構築

## References

- [1] [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
