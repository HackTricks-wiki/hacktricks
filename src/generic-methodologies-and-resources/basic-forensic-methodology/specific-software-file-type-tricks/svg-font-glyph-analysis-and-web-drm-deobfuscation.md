# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 위치가 지정된 glyph run과 요청별 vector glyph 정의(SVG paths)를 제공하며, scraping을 방지하기 위해 요청마다 glyph ID를 무작위화하는 web reader에서 text를 복구하는 실용적인 기법을 설명합니다. 핵심 아이디어는 요청 범위에 종속된 숫자 glyph ID를 무시하고 raster hashing을 통해 시각적 형태를 fingerprint한 다음, reference font atlas와의 SSIM을 사용해 형태를 문자에 매핑하는 것입니다. 동일한 보호 기능을 사용하는 viewer에도 같은 접근 방식을 일반화할 수 있습니다.<sup>[[1]](#references)</sup>

경고: 이러한 기법은 합법적으로 소유한 content를 백업하고, 관련 법률 및 약관을 준수하는 경우에만 사용하세요.

## Acquisition (예: Kindle Cloud Reader)

관찰된 Endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

세션별로 필요한 자료:<sup>[[1]](#references)</sup>
- Browser session cookies (일반 Amazon login)
- startReading API call에서 얻은 rendering token
- renderer에서 사용하는 추가 ADP session token

동작:<sup>[[1]](#references)</sup>
- browser와 동등한 headers 및 cookies를 사용해 각 request를 보내면, 최대 5개 page로 제한된 TAR archive가 반환됩니다.
- 긴 book의 경우 많은 batch가 필요하며, 각 batch는 서로 다른 무작위 glyph ID mapping을 사용합니다.

일반적인 TAR contents:<sup>[[1]](#references)</sup>
- page_data_0_4.json — glyph ID sequence로 구성된 위치 지정 text run (Unicode 아님)
- glyphs.json — 각 glyph 및 fontFamily에 대한 request별 SVG path definition
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mapping

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
glyphs.json 항목 예시:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
anti-scraping path tricks에 대한 참고 사항:<sup>[[1]](#references)</sup>
- 경로에는 많은 vector parser와 naïve path sampling을 혼란스럽게 하는 매우 작은 상대 이동(예: `m3,1 m1,6 m-4,-7`)이 포함될 수 있습니다.
- command/coordinate differencing을 수행하는 대신, 항상 강력한 SVG engine(예: CairoSVG)을 사용해 채워진 완전한 경로를 render해야 합니다.

## naïve decoding이 실패하는 이유

- 요청마다 무작위화되는 glyph substitution: glyph ID→character mapping은 매 batch마다 변경되므로 ID는 전역적으로 의미가 없습니다.<sup>[[1]](#references)</sup>
- 직접적인 SVG coordinate 비교는 취약합니다. 동일한 shape라도 요청마다 numeric coordinates 또는 command encoding이 달라질 수 있습니다.<sup>[[1]](#references)</sup>
- 분리된 glyph에 대한 OCR 성능은 낮고(약 50%), punctuation과 유사하게 생긴 glyph를 혼동하며 ligature를 무시합니다.<sup>[[1]](#references)</sup>

## Working pipeline: request-agnostic glyph normalization 및 mapping

1) 요청별 SVG glyph rasterize
- 제공된 `path`를 사용해 glyph마다 최소 SVG document를 만들고, CairoSVG 또는 까다로운 path sequence를 처리할 수 있는 동등한 engine을 사용해 고정 canvas(예: 512×512)로 render합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 흰색 배경에 검은색으로 채워 render합니다. renderer 및 AA에 따른 artifact를 제거하려면 stroke를 사용하지 마십시오.

2) 요청 간 identity를 위한 Perceptual hashing
- 각 glyph image의 perceptual hash(예: `imagehash.phash`를 통한 pHash)를 계산합니다.<sup>[[3]](#references)</sup>
- hash를 stable ID로 취급합니다. 요청 간 동일한 visual shape는 동일한 perceptual hash로 통합되어 randomized ID를 무력화합니다.

3) Reference font atlas 생성
- 대상 TTF/OTF fonts(예: Bookerly normal/italic/bold/bold-italic)를 다운로드합니다.<sup>[[1]](#references)</sup>
- A–Z, a–z, 0–9, punctuation, special marks(em/en dashes, quotes) 및 명시적 ligature인 `ff`, `fi`, `fl`, `ffi`, `ffl`에 대한 candidates를 render합니다.
- 각 font variant(normal/italic/bold/bold-italic)별로 별도의 atlas를 유지합니다.
- ligature에서 glyph-level fidelity가 필요하다면 적절한 text shaper(HarfBuzz)를 사용합니다. ligature string을 직접 render하고 shaping engine이 이를 처리하도록 하면 Pillow ImageFont를 통한 단순 rasterization으로도 충분할 수 있습니다.

4) SSIM을 사용한 visual similarity matching
- 각 unknown glyph image에 대해 모든 font variant atlas의 모든 candidate image와 SSIM(Structural Similarity Index)을 계산합니다.<sup>[[4]](#references)</sup>
- 가장 높은 점수를 받은 match의 character string을 할당합니다. SSIM은 pixel-exact 비교보다 작은 antialiasing, scale 및 coordinate 차이를 더 잘 흡수합니다.<sup>[[1]](#references)[[4]](#references)</sup>

5) Edge 처리 및 reconstruction
- glyph가 ligature(multi-char)로 mapping되면 decoding 중 이를 확장합니다.<sup>[[1]](#references)</sup>
- run rectangle(top/left/right/bottom)을 사용해 paragraph break(Y delta), alignment(X pattern), style 및 size를 추론합니다.<sup>[[1]](#references)</sup>
- `fontStyle`, `fontWeight`, `fontSize` 및 internal link를 보존하면서 HTML/EPUB로 serialize합니다.<sup>[[1]](#references)</sup>

### Implementation tips

- hashing 및 SSIM 전에 모든 image를 동일한 size와 grayscale로 normalize합니다.
- batch 간 반복되는 glyph에 대해 SSIM을 다시 계산하지 않도록 perceptual hash를 기준으로 cache합니다.
- 더 나은 discrimination을 위해 고품질 raster size(예: 256–512 px)를 사용하고, SSIM을 빠르게 처리해야 할 경우 필요에 따라 downscale합니다.
- Pillow를 사용해 TTF candidates를 render하는 경우 동일한 canvas size를 설정하고 glyph를 중앙에 배치합니다. ascender/descender가 잘리지 않도록 padding을 추가합니다.

<details>
<summary>Python: end-to-end glyph normalization 및 matching(raster hash + SSIM)</summary>
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

## Layout/EPUB 재구성 휴리스틱

소스 보고서는 재구성된 문서의 서식을 유지하기 위해 run geometry, style fields 및 link metadata를 사용했다.<sup>[[1]](#references)</sup>

- Paragraph breaks: 다음 run의 상단 Y가 이전 줄의 baseline을 font size에 상대적인 threshold 이상 초과하면 새 paragraph를 시작한다.<sup>[[1]](#references)</sup>
- Alignment: 왼쪽 정렬 paragraph는 유사한 left X를 기준으로 그룹화하고, 대칭적인 여백으로 centered line을 감지하며, 오른쪽 가장자리를 기준으로 right-aligned line을 감지한다.
- Styling: `fontStyle`/`fontWeight`를 사용해 italic/bold를 유지하고, `fontSize` bucket에 따라 CSS class를 달리해 heading과 본문을 근사한다.
- Links: run에 link metadata(예: `positionId`)가 포함되어 있으면 anchor와 internal href를 생성한다.

## SVG anti-scraping path tricks 완화

- `fill-rule: nonzero`를 사용하는 filled path와 적절한 renderer(CairoSVG, resvg)를 사용한다. path token normalization에 의존하지 않는다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- stroke rendering을 피하고 filled solid에 집중해 micro relative move로 인해 발생하는 hairline artifact를 우회한다.
- batch 간 동일한 shape가 일관되게 rasterize되도록 render마다 안정적인 viewBox를 유지한다.

## Performance notes

- 실제로 books는 수백 개의 unique glyph(예: ligature를 포함해 약 361개)로 수렴한다. perceptual hash를 기준으로 SSIM 결과를 cache한다.<sup>[[1]](#references)</sup>
- 초기 discovery 이후에는 이후 batch가 대부분 알려진 hash를 재사용하므로 decoding은 I/O-bound가 된다.
- 인용된 보고서에서는 평균 SSIM이 약 0.95로 관찰되었으며, 낮은 점수의 match는 manual review 대상으로 표시한다.<sup>[[1]](#references)</sup>

## 다른 viewer로의 일반화

Kindle workflow는 다음 조건을 충족하는 유사한 viewer에도 동일한 normalization을 적용할 수 있음을 시사한다.<sup>[[1]](#references)</sup>
- request-scoped numeric ID가 포함된 positioned glyph run을 반환함
- request별 vector glyph(SVG path 또는 subset font)를 제공함
- request당 page 수를 제한함

…다음과 같은 동일한 normalization으로 처리할 수 있다.
- request별 shape를 rasterize → perceptual hash → shape ID
- font variant별 candidate glyph/ligature atlas
- SSIM(또는 유사한 perceptual metric)을 사용해 character 할당
- run rectangle/style에서 layout 재구성

## Minimal acquisition example (sketch)

browser의 DevTools를 사용해 reader가 `/renderer/render`를 요청할 때 사용하는 정확한 header, cookie 및 token을 캡처한다. 그런 다음 script 또는 curl에서 이를 재현한다.<sup>[[1]](#references)</sup> Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
독자의 요청에 맞게 parameterization(도서 ASIN, page window, viewport)을 조정합니다. 요청당 5페이지 제한을 예상해야 합니다.<sup>[[1]](#references)</sup>

## 달성 가능한 결과

- perceptual hashing을 사용해 100개 이상의 randomized alphabet을 단일 glyph space로 축소합니다.<sup>[[1]](#references)</sup>
- 인용된 920페이지 테스트에서 361개의 고유 glyph가 평균 SSIM 0.9527로 100% 매칭되었습니다.<sup>[[1]](#references)</sup>
- 원본 보고서에 따르면 재구성된 EPUB는 원본과 거의 구별할 수 없습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Amazon Kindle Web Obfuscation을 Reverse Engineering한 이유: 앱이 형편없었기 때문 (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG를 PNG로 렌더링하는 renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill properties](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG rendering library](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
