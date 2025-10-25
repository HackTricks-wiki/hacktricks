# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 위치가 지정된 glyph runs와 요청별 벡터 glyph 정의(SVG paths)를 함께 전송하고, 스크래핑을 방지하기 위해 요청마다 glyph ID를 무작위화하는 웹 리더로부터 텍스트를 복구하는 실용적 기술들을 문서화합니다. 핵심 아이디어는 요청 범위의 숫자 glyph IDs를 무시하고 래스터 해싱(raster hashing)으로 시각적 형태를 지문화한 다음, 참조 font atlas에 대해 SSIM을 사용해 형태를 문자로 매핑하는 것입니다. 이 워크플로우는 Kindle Cloud Reader를 넘어 유사한 보호를 가진 모든 뷰어에 일반화됩니다.

경고: 정당하게 소유한 콘텐츠를 백업하는 경우 및 해당 법률과 약관을 준수하는 경우에만 이러한 기술을 사용하십시오.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Required materials per session:
- Browser session cookies (normal Amazon login)
- Rendering token from a startReading API call
- Additional ADP session token used by the renderer

Behavior:
- Each request, when sent with browser-equivalent headers and cookies, returns a TAR archive limited to 5 pages.
- For a long book you will need many batches; each batch uses a different randomized mapping of glyph IDs.

Typical TAR contents:
- page_data_0_4.json — positioned text runs as sequences of glyph IDs (not Unicode)
- glyphs.json — per-request SVG path definitions for each glyph and fontFamily
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
예시 glyphs.json 항목:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
anti-scraping path tricks에 대한 메모:
- 경로에는 많은 벡터 파서와 단순한 경로 샘플링을 혼란시키는 마이크로 상대 이동이 포함될 수 있음(예: `m3,1 m1,6 m-4,-7`).
- 명령/좌표 차분을 하지 말고 강력한 SVG 엔진(예: CairoSVG)으로 항상 채워진 완전한 경로를 렌더링하세요.

## Why naïve decoding fails

- Per-request randomized glyph substitution: glyph ID→character 매핑이 배치마다 무작위화됨; ID는 전역적으로 의미가 없음.
- Direct SVG coordinate comparison은 취약함: 동일한 모양이라도 요청마다 수치 좌표나 명령 인코딩이 다를 수 있음.
- OCR on isolated glyphs 성능이 낮음(≈50%): 구두점과 유사 글리프를 혼동하고 ligatures를 무시함.

## Working pipeline: request-agnostic glyph normalization and mapping

1) Rasterize per-request SVG glyphs
- 제공된 `path`로 글리프별 최소 SVG 문서를 만들고 CairoSVG 또는 까다로운 경로 시퀀스를 처리하는 동등한 엔진을 사용해 고정 캔버스(예: 512×512)로 렌더링합니다.
- 채우기는 검정/흰색으로 렌더링하고, 렌더러와 AA에 따른 아티팩트를 제거하기 위해 strokes는 피합니다.

2) Perceptual hashing for cross-request identity
- 각 글리프 이미지에 대해 perceptual hash(예: `imagehash.phash`를 통한 pHash)를 계산합니다.
- 해시를 안정적 ID로 취급하세요: 요청 간 동일한 시각적 모양은 동일한 perceptual hash로 수렴하여 무작위화된 ID를 무력화합니다.

3) Reference font atlas generation
- 대상 TTF/OTF 폰트를 다운로드합니다(예: Bookerly normal/italic/bold/bold-italic).
- A–Z, a–z, 0–9, punctuation, 특수 기호(em/en dashes, quotes) 및 명시적 ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`에 대한 후보를 렌더링합니다.
- 폰트 변형(normal/italic/bold/bold-italic)별로 별도 아틀라스를 유지합니다.
- ligatures에 대해 글리프 수준의 충실도가 필요하면 proper text shaper(HarfBuzz)를 사용하세요; 단순히 ligature 문자열을 직접 렌더링하고 shaping 엔진이 이를 해결하면 Pillow ImageFont로의 간단한 래스터화도 충분할 수 있습니다.

4) Visual similarity matching with SSIM
- 각 미확인 글리프 이미지에 대해 모든 폰트 변형 아틀라스의 후보 이미지들과 SSIM(Structural Similarity Index)을 계산합니다.
- 최고 점수를 받은 매치의 문자 문자열을 할당합니다. SSIM은 픽셀 정확 비교보다 작은 안티앨리어싱, 스케일, 좌표 차이를 더 잘 흡수합니다.

5) Edge handling and reconstruction
- 글리프가 ligature(다중 문자)로 매핑되면 디코딩 시 확장합니다.
- 런 사각형(top/left/right/bottom)을 사용해 문단 구분(Y 델타), 정렬(X 패턴), 스타일 및 크기를 추론합니다.
- `fontStyle`, `fontWeight`, `fontSize` 및 내부 링크를 보존하여 HTML/EPUB로 직렬화합니다.

### Implementation tips

- 해싱 및 SSIM 전에 모든 이미지를 동일한 크기와 그레이스케일로 정규화하세요.
- 퍼셉추얼 해시로 캐시하여 배치 간 반복 글리프에 대해 SSIM 재계산을 피하세요.
- 더 나은 식별을 위해 고품질 래스터 크기(예: 256–512 px)를 사용하고, SSIM 가속을 위해 필요 시 축소하세요.
- Pillow로 TTF 후보를 렌더링하는 경우 동일한 캔버스 크기를 설정하고 글리프를 가운데에 배치하며, ascender/descender가 잘리지 않도록 패딩하세요.

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

## Layout/EPUB reconstruction heuristics

- Paragraph breaks: 다음 run의 top Y가 이전 줄의 baseline을 폰트 크기에 상대적인 임계값 이상으로 초과하면 새 문단을 시작합니다.
- Alignment: 왼쪽 정렬 문단은 유사한 left X로 그룹화합니다; 가운데 정렬은 대칭 여백으로 감지하고; 오른쪽 정렬은 오른쪽 가장자리로 감지합니다.
- Styling: 기울임/굵게는 `fontStyle`/`fontWeight`로 보존합니다; 제목과 본문을 근사화하기 위해 `fontSize` 버킷별로 CSS 클래스를 달리합니다.
- Links: runs에 링크 메타데이터(예: `positionId`)가 포함되어 있으면 앵커와 내부 href를 생성합니다.

## Mitigating SVG anti-scraping path tricks

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). 경로 토큰 정규화에 의존하지 마세요.
- Avoid stroke rendering; 채워진 솔리드에 집중하여 미세한 상대 이동으로 발생하는 헤어라인 아티팩트를 회피하세요.
- 렌더마다 안정적인 `viewBox`를 유지하여 동일한 도형이 배치 간에 일관되게 래스터화되도록 합니다.

## Performance notes

- 실무에서는 책이 수백 개의 고유 글리프(예: 합자 포함 약 361개)로 수렴합니다. SSIM 결과를 perceptual hash로 캐시하세요.
- 초기 발견 이후 이후 배치들은 주로 알려진 해시를 재사용하므로 디코딩이 I/O-bound가 됩니다.
- 평균 SSIM ≈0.95는 강한 신호입니다; 점수가 낮은 매치는 수동 검토를 위해 플래그하는 것을 고려하세요.

## Generalization to other viewers

다음을 제공하는 모든 시스템:
- 요청 범위의 숫자 ID와 함께 위치 지정된 glyph runs를 반환
- 요청별 벡터 글리프(SVG paths 또는 subset fonts)를 전송
- 대량 추출을 방지하기 위해 요청당 페이지 수를 제한

…같은 정규화로 처리할 수 있습니다:
- 요청별 도형 래스터화 → perceptual hash → shape ID
- 글꼴 변형별 후보 글리프/합자 아틀라스
- 문자를 할당하기 위한 SSIM(또는 유사한 perceptual metric)
- run 사각형/스타일로부터 레이아웃 재구성

## Minimal acquisition example (sketch)

브라우저의 DevTools를 사용하여 reader가 `/renderer/render`를 요청할 때 사용되는 정확한 헤더, 쿠키 및 토큰을 캡처하세요. 그런 다음 스크립트나 curl에서 이를 복제하세요. 예시 개요:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
독자의 요청에 맞게 파라미터(책 ASIN, 페이지 윈도우, viewport)를 조정하세요. 요청당 최대 5페이지 제한이 적용됩니다.

## 달성 가능한 결과

- perceptual hashing을 통해 100개 이상의 무작위화된 알파벳을 단일 글리프 공간으로 축소
- 아틀라스가 합자(ligatures)와 변형(variants)을 포함할 때 고유 글리프를 평균 SSIM ~0.95로 100% 매핑
- 재구성된 EPUB/HTML이 원본과 시각적으로 구별 불가

## References

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
