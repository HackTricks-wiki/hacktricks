# SVG/Font Glyph 分析与 Web DRM 去混淆（Raster Hashing + SSIM）

{{#include ../../../banners/hacktricks-training.md}}

本页记录了从 Web reader 中恢复文本的实用技术。这类 reader 会发送带有位置的 glyph runs，以及每次请求对应的 vector glyph 定义（SVG paths），并通过每次请求随机化 glyph ID 来阻止 scraping。核心思路是忽略请求范围内的数字 glyph ID，通过 Raster Hashing 对视觉形状进行指纹识别，然后使用 SSIM 将这些形状与 reference font atlas 进行比对，从而映射到字符。相同方法也可能适用于采用类似保护机制的 viewer。<sup>[[1]](#references)</sup>

警告：仅可使用这些技术备份你合法拥有的内容，并遵守适用的法律和条款。

## Acquisition（示例：Kindle Cloud Reader）

观察到的 Endpoint：<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

每个 session 所需的材料：<sup>[[1]](#references)</sup>
- Browser session cookies（正常的 Amazon login）
- startReading API call 返回的 rendering token
- renderer 使用的额外 ADP session token

行为：<sup>[[1]](#references)</sup>
- 每次请求在携带与 browser 等效的 headers 和 cookies 时，都会返回一个最多包含 5 页的 TAR archive。
- 对于较长的书籍，需要进行多次 batches；每个 batch 都会使用不同的随机 glyph ID 映射。

典型的 TAR 内容：<sup>[[1]](#references)</sup>
- page_data_0_4.json — 以 glyph ID 序列表示的带位置文本 runs（不是 Unicode）
- glyphs.json — 每个 glyph 和 fontFamily 对应的 per-request SVG path 定义
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mappings

示例 page run 结构：<sup>[[1]](#references)</sup>
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
示例 glyphs.json 条目：<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
关于 anti-scraping path tricks 的说明：<sup>[[1]](#references)</sup>
- Paths 可能包含微小的相对移动（例如 `m3,1 m1,6 m-4,-7`），这会干扰许多 vector parser 和 naïve path sampling。
- 始终使用可靠的 SVG engine（例如 CairoSVG）渲染完整的 filled paths，而不要进行 command/coordinate differencing。

## naïve decoding 失败的原因

- 每个请求都会随机替换 glyph：glyph ID→character 的 mapping 每批次都会变化；ID 在全局范围内没有意义。<sup>[[1]](#references)</sup>
- 直接比较 SVG coordinate 很脆弱：相同的形状在每次请求中可能具有不同的 numeric coordinates 或 command encoding。<sup>[[1]](#references)</sup>
- 对孤立 glyph 进行 OCR 的效果较差（≈50%），容易混淆 punctuation 和外观相似的 glyph，并且会忽略 ligatures。<sup>[[1]](#references)</sup>

## Working pipeline：request-agnostic glyph normalization and mapping

1) Rasterize per-request SVG glyphs
- 为每个 glyph 构建一个最小 SVG document，其中包含提供的 `path`，并使用 CairoSVG 或能够处理复杂 path sequences 的等效 engine 将其渲染到固定 canvas（例如 512×512）。<sup>[[1]](#references)[[2]](#references)</sup>
- 将 filled glyph 渲染为黑色、背景为白色；避免使用 strokes，以消除依赖 renderer 和 AA 的 artifacts。

2) 使用 Perceptual hashing 进行跨请求 identity 识别
- 对每个 glyph image 计算 perceptual hash（例如通过 `imagehash.phash` 使用 pHash）。<sup>[[3]](#references)</sup>
- 将 hash 视为 stable ID：不同请求中的相同 visual shape 会归并为相同的 perceptual hash，从而规避 randomized IDs。

3) Reference font atlas generation
- 下载目标 TTF/OTF fonts（例如 Bookerly normal/italic/bold/bold-italic）。<sup>[[1]](#references)</sup>
- 为 A–Z、a–z、0–9、punctuation、special marks（em/en dashes、quotes）以及显式 ligatures 生成 candidates：`ff`、`fi`、`fl`、`ffi`、`ffl`。
- 为每个 font variant（normal/italic/bold/bold-italic）分别保留 atlas。
- 如果需要 ligatures 的 glyph-level fidelity，请使用 proper text shaper（HarfBuzz）；如果直接渲染 ligature strings 并由 shaping engine 解析它们，使用 Pillow ImageFont 进行简单 rasterization 也可能足够。

4) 使用 SSIM 进行 visual similarity matching
- 对每个 unknown glyph image，针对所有 font variant atlases 中的全部 candidate images 计算 SSIM（Structural Similarity Index）。<sup>[[4]](#references)</sup>
- 将得分最高的 match 的 character string 分配给该 glyph。与 pixel-exact comparisons 相比，SSIM 能更好地吸收细微的 antialiasing、scale 和 coordinate 差异。<sup>[[1]](#references)[[4]](#references)</sup>

5) Edge handling and reconstruction
- 当某个 glyph 映射到 ligature（multi-char）时，在 decoding 过程中将其展开。<sup>[[1]](#references)</sup>
- 使用 run rectangles（top/left/right/bottom）推断 paragraph breaks（Y deltas）、alignment（X patterns）、style 和 sizes。<sup>[[1]](#references)</sup>
- 序列化为 HTML/EPUB，同时保留 `fontStyle`、`fontWeight`、`fontSize` 和 internal links。<sup>[[1]](#references)</sup>

### Implementation tips

- 在 hashing 和 SSIM 之前，将所有 images normalize 为相同尺寸和 grayscale。
- 按 perceptual hash 进行 cache，避免对不同 batches 中重复出现的 glyph 重新计算 SSIM。
- 使用高质量的 raster size（例如 256–512 px）以提高 discrimination；在 SSIM 之前可按需 downscale，以加快处理速度。
- 如果使用 Pillow 渲染 TTF candidates，请设置相同的 canvas size 并将 glyph 居中；添加 padding 以避免 ascenders/descenders 被裁剪。

<details>
<summary>Python：端到端 glyph normalization 和 matching（raster hash + SSIM）</summary>
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

## Layout/EPUB 重建启发式方法

源报告使用 run geometry、style fields 和 link metadata 来保留重建文档的格式。<sup>[[1]](#references)</sup>

- 段落断开：如果下一个 run 的顶部 Y 坐标超过上一行 baseline（相对于 font size）的阈值，则开始新段落。<sup>[[1]](#references)</sup>
- 对齐：按相近的左侧 X 坐标对左对齐段落进行分组；通过对称边距检测居中行；通过右边缘检测右对齐。
- 样式：通过 `fontStyle`/`fontWeight` 保留 italic/bold；根据 `fontSize` buckets 调整 CSS classes，以近似 headings 与正文。
- Links：如果 runs 包含 link metadata（例如 `positionId`），则生成 anchors 和内部 hrefs。

## 缓解 SVG anti-scraping path tricks

- 使用带有 `fill-rule: nonzero` 的 filled paths 和 proper renderer（CairoSVG、resvg）。不要依赖 path token normalization。<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 避免 stroke rendering；专注于 filled solids，以规避由微小 relative moves 引起的 hairline artifacts。
- 每次 render 使用稳定的 viewBox，确保相同 shapes 在不同 batches 中保持一致的 rasterization。

## Performance notes

- 实际上，books 最终会收敛到几百个 unique glyphs（例如，包括 ligatures 在内约 361 个）。通过 perceptual hash 缓存 SSIM 结果。<sup>[[1]](#references)</sup>
- 初始 discovery 后，后续 batches 主要会重新使用已知 hashes；decoding 会受 I/O 限制。
- 引用的报告观察到平均 SSIM 约为 0.95；对低分匹配进行标记，以便 manual review。<sup>[[1]](#references)</sup>

## Generalization to other viewers

Kindle workflow 表明，当类似 viewers 具备以下条件时，可能适用相同的 normalization：<sup>[[1]](#references)</sup>
- 返回带位置的 glyph runs，并使用 request-scoped numeric IDs
- 传输 per-request vector glyphs（SVG paths 或 subset fonts）
- 限制每次 request 的 pages 数量

…可以使用相同的 normalization 处理：
- Rasterize per-request shapes → perceptual hash → shape ID
- 为每个 font variant 建立 candidate glyphs/ligatures 的 Atlas
- 使用 SSIM（或类似的 perceptual metric）分配 characters
- 根据 run rectangles/styles 重建 layout

## Minimal acquisition example (sketch)

使用浏览器的 DevTools 捕获 reader 请求 `/renderer/render` 时使用的 exact headers、cookies 和 tokens。然后通过 script 或 curl 复现这些内容。<sup>[[1]](#references)</sup> 示例大纲：
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
调整参数化（book ASIN、page window、viewport）以匹配读者的请求。每次请求最多处理 5 页。<sup>[[1]](#references)</sup>

## 可实现的结果

- 通过感知哈希将 100 多种随机化字母表合并到单一 glyph 空间。<sup>[[1]](#references)</sup>
- 在引用的 920 页测试中，匹配到 361 个唯一 glyph（100%），平均 SSIM 为 0.9527。<sup>[[1]](#references)</sup>
- 源报告称，重建的 EPUB 与原始版本几乎无法区分。<sup>[[1]](#references)</sup>

## References

- [1] [我如何逆向 Amazon 的 Kindle Web 混淆，因为他们的 App 太糟糕了（Pixelmelt）](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG 到 PNG 渲染器](https://cairosvg.org/)
- [3] [imagehash – 感知图像哈希（pHash）](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – 结构相似性指数（SSIM）](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill 属性](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG 渲染库](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
