# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

本页记录了从那些以带定位的字形序列以及每次请求提供向量字形定义（SVG 路径）并对每次请求随机化 glyph ID 以防止抓取的 web 阅读器中恢复文本的实用技术。核心思路是忽略请求范围的数字 glyph ID，通过 raster hashing 对视觉形状进行指纹化，然后用 SSIM 将形状与参考字体图集比对以映射到字符。该工作流不仅适用于 Kindle Cloud Reader，也可推广到任何具有类似防护的查看器。

警告：仅在你合法拥有内容且符合适用法律和条款的情况下使用这些技术进行备份。

## 获取 (示例：Kindle Cloud Reader)

Endpoint observed:
- https://read.amazon.com/renderer/render

每个会话所需材料：
- 浏览器会话 cookies（常规 Amazon 登录）
- 来自 startReading API 调用的 rendering token
- renderer 使用的额外 ADP 会话 token

行为：
- 每个请求在使用与浏览器等效的 headers 和 cookies 发送时，会返回一个被限制为 5 页的 TAR 归档。
- 对于内容较长的书籍，你需要多次分批；每批使用不同的随机化 glyph ID 映射。

典型的 TAR 内容：
- page_data_0_4.json — 带定位的文本运行，以 glyph ID 序列表示（非 Unicode）
- glyphs.json — 每次请求为每个 glyph 和 fontFamily 提供的 SVG 路径定义
- toc.json — 目录
- metadata.json — 书籍元数据
- location_map.json — logical→visual 位置映射

示例页面运行结构：
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
示例 glyphs.json 条目：
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
关于反爬虫路径技巧的说明：
- 路径可能包含微小的相对移动（例如 `m3,1 m1,6 m-4,-7`），这会让许多向量解析器和简单的路径采样器混淆。
- 总是使用健壮的 SVG 引擎（例如 CairoSVG）渲染填充的完整路径，而不是通过命令/坐标差分来处理。

## 为什么简单解码会失败

- 每次请求的随机字形替换：字形 ID→字符 映射在每个批次中变化；ID 在全局没有意义。
- 直接比较 SVG 坐标很脆弱：相同的形状在每次请求中可能在数字坐标或命令编码上不同。
- 对独立字形进行 OCR 的效果很差（≈50%），会混淆标点和相似字形，而且会忽略连字。

## 工作流程：与请求无关的字形归一化与映射

1) Rasterize per-request SVG glyphs
- 针对每个字形构建一个最小的 SVG 文档，包含提供的 `path`，并使用 CairoSVG 或能处理复杂路径序列的等效引擎在固定画布上（例如 512×512）进行渲染。
- 以白底黑填充渲染；避免使用描边，以消除与渲染器和抗锯齿相关的伪影。

2) Perceptual hashing for cross-request identity
- 对每个字形图像计算感知哈希（例如使用 `imagehash.phash` 的 pHash）。
- 将该哈希视为稳定 ID：跨请求相同的视觉形状会映射到相同的感知哈希，从而对抗随机化的 ID。

3) Reference font atlas generation
- 下载目标 TTF/OTF 字体（例如 Bookerly normal/italic/bold/bold-italic）。
- 渲染 A–Z、a–z、0–9、标点、特殊符号（em/en dashes、引号）以及显式连字的候选字形：`ff`, `fi`, `fl`, `ffi`, `ffl`。
- 为每个字体变体（normal/italic/bold/bold-italic）保留独立的图集。
- 如果需要对连字实现字形级别的保真，使用专业的 text shaper（HarfBuzz）；如果你直接渲染连字字符串并且 shaping 引擎能解析它们，使用 Pillow ImageFont 的简单光栅化也可能足够。

4) Visual similarity matching with SSIM
- 对于每个未知字形图像，计算其与所有字体变体图集中所有候选图像之间的 SSIM（结构相似性指数）。
- 将得分最高的匹配项对应的字符字符串分配给该字形。与像素精确比较相比，SSIM 更能容忍小的抗锯齿、缩放和坐标差异。

5) Edge handling and reconstruction
- 当字形对应到连字（多字符）时，在解码过程中展开它。
- 使用运行矩形（top/left/right/bottom）来推断段落分隔（Y 偏移）、对齐方式（X 模式）、样式和大小。
- 序列化为 HTML/EPUB，同时保留 `fontStyle`、`fontWeight`、`fontSize` 和内部链接。

### 实现建议

- 在计算哈希和 SSIM 之前，将所有图像归一化为相同尺寸并转为灰度。
- 按感知哈希进行缓存，以避免对跨批次重复字形重复计算 SSIM。
- 使用高质量的光栅尺寸（例如 256–512 px）以获得更好的区分度；在计算 SSIM 前根据需要下采样以加速。
- 如果使用 Pillow 渲染 TTF 候选字形，设置相同的画布尺寸并将字形居中；留白以避免截断上升/下降部分。

<details>
<summary>Python: 端到端字形归一化与匹配（raster hash + SSIM）</summary>
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

## Layout/EPUB reconstruction heuristics

- Paragraph breaks: 如果下一个 run 的 top Y 超过上一行 baseline 一个阈值（相对于字体大小），则开始新段落。
- Alignment: 通过相似的 left X 将左对齐段落分组；通过对称的边距检测居中行；通过右边缘检测右对齐。
- Styling: 通过 `fontStyle`/`fontWeight` 保留斜体/粗体；按 `fontSize` 桶划分 CSS 类以近似区分标题和正文。
- Links: 如果 runs 包含链接元数据（例如 `positionId`），则生成锚点和内部 href。

## Mitigating SVG anti-scraping path tricks

- 使用填充路径并设置 `fill-rule: nonzero`，以及合适的 renderer（CairoSVG, resvg）。不要依赖路径标记规范化。
- 避免 stroke 渲染；专注于填充实心以绕过由微小相对移动引起的发丝状伪影。
- 在每次渲染中保持稳定的 viewBox，以便相同形状在不同批次中光栅化一致。

## Performance notes

- 在实践中，书籍通常收敛到几百个唯一字形（例如包含连字约 ~361 个）。通过感知哈希缓存 SSIM 结果。
- 初次发现后，后续批次主要重用已知哈希；解码过程变为 I/O 受限。
- 平均 SSIM ≈0.95 是强信号；考虑将低得分匹配标记为人工复查。

## Generalization to other viewers

任何满足以下条件的系统：
- 返回带有请求作用域数字 ID 的定位字形 runs
- 每次请求下发向量字形（SVG paths 或子集字体）
- 限制每次请求的页面数以防止批量导出

…都可以用相同的规范化方法处理：
- 对每次请求的形状进行光栅化 → 感知哈希 → shape ID
- 为每个字体变体构建候选字形/连字图谱
- 使用 SSIM（或类似的感知度量）分配字符
- 从 run 的矩形/样式重构版面

## Minimal acquisition example (sketch)

使用浏览器的 DevTools 捕获 reader 在请求 `/renderer/render` 时使用的精确 headers、cookies 和 tokens。然后在脚本或 curl 中复现这些。示例大纲：
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
根据读者的请求调整参数化（book ASIN、page window、viewport）。请注意每次请求上限为 5 页。

## 可达成的结果

- 通过 perceptual hashing 将 100 多个随机化字母表折叠到单一字形空间
- 当字体图集包含连字和变体时，唯一字形可实现 100% 映射，平均 SSIM 约为 0.95
- 重建后的 EPUB/HTML 在视觉上与原始文件无法区分

## 参考资料

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
