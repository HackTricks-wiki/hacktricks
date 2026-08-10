# SVG/Font Glyph Analysis と Web DRM Deobfuscation (Raster Hashing + SSIM)

このページでは、位置情報付きの glyph run とリクエストごとの vector glyph 定義（SVG paths）を提供し、さらに scraping 防止のためリクエストごとに glyph ID をランダム化する web reader から、テキストを復元する実用的な技法を説明します。基本的な考え方は、リクエスト単位で変化する数値の glyph ID を無視し、Raster Hashing によって視覚的な形状を fingerprint 化したうえで、reference font atlas に対する SSIM により形状を文字へマッピングすることです。同様の保護機構を備えた viewer にも、この手法を応用できる可能性があります。<sup>[[1]](#references)</sup>

警告: これらの技法は、自身が合法的に所有するコンテンツのバックアップ、および適用される法律と利用規約の遵守のためにのみ使用してください。

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Required materials per session:<sup>[[1]](#references)</sup>
- Browser session cookies（通常の Amazon login）
- startReading API call から取得した rendering token
- renderer が使用する追加の ADP session token

Behavior:<sup>[[1]](#references)</sup>
- Browser と同等の headers と cookies を付けて各 request を送信すると、5 ページに制限された TAR archive が返されます。
- 長い book では多数の batch が必要になり、各 batch では異なるランダム化された glyph ID の mapping が使用されます。

Typical TAR contents:<sup>[[1]](#references)</sup>
- page_data_0_4.json — glyph ID の sequence として格納された、位置情報付きの text run（Unicode ではありません）
- glyphs.json — 各 glyph と fontFamily に対応する、request ごとの SVG path 定義
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
アンチスクレイピングのパスに関するトリックのメモ:<sup>[[1]](#references)</sup>
- パスには、微細な相対移動（例: `m3,1 m1,6 m-4,-7`）が含まれる場合があり、多くのベクターパーサーや単純なパスサンプリングを混乱させます。
- コマンドや座標の差分を取るのではなく、必ず堅牢な SVG エンジン（例: CairoSVG）で塗りつぶした完全なパスをレンダリングしてください。

## 単純なデコードが失敗する理由

- リクエストごとにランダム化された glyph substitution: glyph ID→character のマッピングはバッチごとに変化するため、ID にグローバルな意味はありません。<sup>[[1]](#references)</sup>
- SVG 座標の直接比較は脆弱です。同一の形状でも、リクエストごとに数値座標やコマンドのエンコーディングが異なる可能性があります。<sup>[[1]](#references)</sup>
- 分離された glyph に対する OCR の性能は低く（約50%）、句読点や似た glyph を取り違え、ligature を無視します。<sup>[[1]](#references)</sup>

## 実用的なパイプライン: リクエストに依存しない glyph の正規化とマッピング

1) リクエストごとの SVG glyph をラスタライズする
- 各 glyph について、提供された `path` を含む最小限の SVG ドキュメントを作成し、CairoSVG または、複雑なパスシーケンスを処理できる同等のエンジンを使って、固定キャンバス（例: 512×512）にレンダリングします。<sup>[[1]](#references)[[2]](#references)</sup>
- 白地に黒の塗りつぶしでレンダリングし、renderer や AA に依存するアーティファクトを除去するため、stroke は避けます。

2) リクエスト間の同一性を判定するための知覚ハッシュ
- 各 glyph 画像の perceptual hash（例: `imagehash.phash` による pHash）を計算します。<sup>[[3]](#references)</sup>
- hash を安定した ID として扱います。リクエスト間で同じ視覚的形状は同じ perceptual hash にまとめられるため、ランダム化された ID を無効化できます。

3) 参照 font atlas の生成
- 対象の TTF/OTF fonts（例: Bookerly normal/italic/bold/bold-italic）をダウンロードします。<sup>[[1]](#references)</sup>
- A–Z、a–z、0–9、句読点、特殊記号（em/en dashes、引用符）、および明示的な ligature: `ff`、`fi`、`fl`、`ffi`、`ffl` の候補をレンダリングします。
- font variant（normal/italic/bold/bold-italic）ごとに別々の atlas を維持します。
- ligature について glyph レベルの忠実度が必要な場合は、適切な text shaper（HarfBuzz）を使用します。ImageFont を使った Pillow による単純なラスタライズでも、ligature 文字列を直接レンダリングし、shaping engine が解決してくれるなら十分な場合があります。

4) SSIM による視覚的類似度マッチング
- 各未知の glyph 画像について、すべての font variant atlas にあるすべての候補画像との SSIM（Structural Similarity Index）を計算します。<sup>[[4]](#references)</sup>
- 最も高いスコアの候補に対応する character string を割り当てます。SSIM は、pixel-exact な比較よりも、アンチエイリアシング、スケール、座標の小さな差異を適切に吸収します。<sup>[[1]](#references)[[4]](#references)</sup>

5) エッジ処理と再構築
- glyph が ligature（複数文字）にマッピングされた場合は、デコード時に展開します。<sup>[[1]](#references)</sup>
- run rectangle（top/left/right/bottom）を使って、段落区切り（Y の差分）、配置（X のパターン）、style、サイズを推測します。<sup>[[1]](#references)</sup>
- `fontStyle`、`fontWeight`、`fontSize`、および内部リンクを維持したまま、HTML/EPUB にシリアライズします。<sup>[[1]](#references)</sup>

### 実装のヒント

- hash と SSIM の前に、すべての画像を同じサイズと grayscale に正規化します。
- バッチ間で繰り返される glyph の SSIM 再計算を避けるため、perceptual hash をキーにしてキャッシュします。
- 識別精度を高めるため、高品質なラスタライズサイズ（例: 256–512 px）を使用し、SSIM を高速化する必要に応じて縮小します。
- Pillow で TTF の候補をレンダリングする場合は、同じキャンバスサイズを設定して glyph を中央に配置し、ascender/descender が切り取られないようにパディングします。

<details>
<summary>Python: glyph のエンドツーエンドの正規化とマッチング（raster hash + SSIM）</summary>
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

## Layout/EPUB再構成のヒューリスティック

元のレポートでは、再構成したドキュメントのフォーマットを保持するために、runのジオメトリ、styleフィールド、link metadataを使用していました。<sup>[[1]](#references)</sup>

- Paragraph breaks: 次のrunの上端Yが、前の行のbaselineをfont sizeに対する閾値以上に超えている場合、新しい段落を開始します。<sup>[[1]](#references)</sup>
- Alignment: 左揃えの段落は、左Xが近いものごとにグループ化します。対称的な余白から中央揃えの行を検出し、右端から右揃えを検出します。
- Styling: `fontStyle`/`fontWeight`でitalic/boldを保持し、`fontSize`のバケットごとにCSSクラスを変えて、headingと本文を近似します。
- Links: runにlink metadata（例: `positionId`）が含まれている場合、anchorと内部hrefを出力します。

## SVG anti-scraping path tricksの緩和

- `fill-rule: nonzero`を指定したfilled pathと適切なrenderer（CairoSVG、resvg）を使用します。path token normalizationに依存しないでください。<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- stroke renderingを避け、micro relative moveによるhairline artifactを回避するため、filled solidに集中します。
- レンダリングごとに安定したviewBoxを維持し、同一のshapeがbatch間で一貫してrasterizeされるようにします。

## Performance notes

- 実際には、booksは数百個のunique glyph（ligatureを含めて約361個など）に収束します。perceptual hashによってSSIMの結果をcacheしてください。<sup>[[1]](#references)</sup>
- 初期のdiscovery後は、後続のbatchで既知のhashが主に再利用されるため、decodingはI/O-boundになります。
- 引用されたレポートでは、平均SSIMは約0.95でした。スコアの低いmatchにはmanual reviewのフラグを立ててください。<sup>[[1]](#references)</sup>

## 他のviewerへの一般化

Kindle workflowから、以下の条件を満たす類似viewerは同じnormalizationを適用できる可能性があります。<sup>[[1]](#references)</sup>
- request-scoped numeric IDを持つpositioned glyph runを返す
- requestごとのvector glyph（SVG pathまたはsubset font）を提供する
- requestごとのpage数に上限を設ける

…これらは、同じnormalizationで処理できます。
- requestごとのshapeをrasterize → perceptual hash → shape ID
- font variantごとのcandidate glyph/ligatureのatlas
- SSIM（または同様のperceptual metric）でcharacterを割り当てる
- run rectangle/styleからlayoutを再構成する

## Minimal acquisition example（sketch）

browserのDevToolsを使用して、readerが`/renderer/render`をrequestする際に使用する正確なheaders、cookies、tokensをcaptureします。その後、scriptまたはcurlからそれらを再現します。<sup>[[1]](#references)</sup> Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
パラメーター（book ASIN、page window、viewport）を読者のリクエストに合わせて調整します。1リクエストあたり最大5ページまでです。<sup>[[1]](#references)</sup>

## Results achievable

- perceptual hashing により、100種類以上のランダム化された alphabet を単一の glyph space に統合できます。<sup>[[1]](#references)</sup>
- 引用された920ページのテストでは、361個の unique glyph が平均 SSIM 0.9527で100%マッチしました。<sup>[[1]](#references)</sup>
- source report では、再構築された EPUB はオリジナルとほぼ見分けがつかないと説明されています。<sup>[[1]](#references)</sup>

## References

- [1] [AmazonのKindle Web Obfuscationを逆解析した理由：Appの出来が悪かったため（Pixelmelt）](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVGからPNGへのrenderer](https://cairosvg.org/)
- [3] [imagehash – perceptual image hashing（pHash）](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index（SSIM）](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill properties](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG rendering library](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
