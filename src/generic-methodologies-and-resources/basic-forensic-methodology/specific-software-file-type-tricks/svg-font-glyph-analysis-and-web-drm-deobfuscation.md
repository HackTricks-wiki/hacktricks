# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ця сторінка документує практичні техніки для відновлення тексту з web readers, які передають positioned glyph runs разом з per-request vector glyph definitions (SVG paths) і які рандомізують glyph IDs для кожного запиту, щоб запобігти скрапінгу. Основна ідея — ігнорувати request-scoped numeric glyph IDs і фіингерпринтити візуальні форми за допомогою raster hashing, а потім зіставляти форми з символами за допомогою SSIM проти reference font atlas. Робочий процес узагальнюється поза Kindle Cloud Reader до будь-якого viewer з подібними захистами.

Warning: Використовуйте ці техніки лише для резервного копіювання контенту, яким ви легітимно володієте, і в відповідності до застосовних законів та умов.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render]

Потрібні матеріали на сесію:
- Browser session cookies (звичайний Amazon login)
- Rendering token з виклику startReading API
- Додатковий ADP session token, який використовує renderer

Поведінка:
- Кожен запит, коли його надсилають з заголовками та cookies, еквівалентними браузеру, повертає TAR-архів, обмежений 5 сторінками.
- Для довгої книги вам знадобиться багато батчів; кожен батч використовує різне рандомізоване відображення glyph IDs.

Типовий вміст TAR:
- page_data_0_4.json — positioned text runs як послідовності glyph IDs (не Unicode)
- glyphs.json — per-request SVG path definitions для кожного glyph і fontFamily
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
Приклад запису glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Нотатки щодо трюків зі шляхами проти скрейпінгу:
- Шляхи можуть містити мікро-релятивні переміщення (наприклад, `m3,1 m1,6 m-4,-7`), які плутають багато векторних парсерів та наївне семплування path.
- Завжди рендерте заповнені повні шляхи за допомогою надійного SVG-двигуна (наприклад, CairoSVG) замість того, щоб робити різницювання команд/координат.

## Чому наївне декодування не працює

- Пер-запит випадкова підстановка glyph-ів: відображення glyph ID→character змінюється кожною партією; ID не мають глобального сенсу.
- Пряме порівняння координат SVG крихке: однакові форми можуть відрізнятися числовими координатами або кодуванням команд у різних запитах.
- OCR на ізольованих glyph-ах працює погано (≈50%), плутає розділові знаки та схожі за виглядом glyph-и, і ігнорує ligatures.

## Робочий пайплайн: запит-незалежна нормалізація та зіставлення glyph-ів

1) Растеризація SVG glyph-ів для кожного запиту
- Побудуйте мінімальний SVG-документ для кожного glyph з наданим `path` і відрендерте на фіксований канвас (наприклад, 512×512) за допомогою CairoSVG або еквівалентного двигуна, який коректно обробляє складні послідовності path.
- Рендерте заповненими чорним на білому; уникайте stroke, щоб усунути залежні від рендера та AA артефакти.

2) Перцепційне хешування для ідентифікації між запитами
- Обчисліть перцепційний хеш (наприклад, pHash через `imagehash.phash`) кожного зображення glyph-а.
- Розглядайте хеш як стабільний ID: однаковий візуальний контур у різних запитах зводиться до того ж перцепційного хешу, що нейтралізує випадкові ID.

3) Генерація референсного шрифтового атласу
- Завантажте цільові TTF/OTF шрифти (наприклад, Bookerly normal/italic/bold/bold-italic).
- Відрендерте кандидати для A–Z, a–z, 0–9, пунктуації, спеціальних знаків (em/en dashes, quotes) та явних ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Тримайте окремі атласи для кожної варіанти шрифту (normal/italic/bold/bold-italic).
- Використовуйте коректний text shaper (HarfBuzz), якщо вам потрібна точність на рівні glyph для ligatures; просте растерне рендерення через Pillow ImageFont може бути достатнім, якщо ви рендерите рядки з ligature безпосередньо і shaping engine їх розв’язує.

4) Візуальне зіставлення за допомогою SSIM
- Для кожного невідомого зображення glyph обчисліть SSIM (Structural Similarity Index) проти всіх кандидатів у всіх атласах варіантів шрифта.
- Призначайте рядок символів з найкращою оцінкою. SSIM поглинає невеликі відмінності, пов’язані з антіаліасінгом, масштабом і координатами краще, ніж піксельно-точне порівняння.

5) Обробка крайових випадків та реконструкція
- Коли glyph мапиться на ligature (багатосимвольний), розгорніть її під час декодування.
- Використовуйте run rectangles (top/left/right/bottom) щоб вивести розриви абзаців (дельти по Y), вирівнювання (патерни по X), стиль і розміри.
- Серіалізуйте у HTML/EPUB з збереженням `fontStyle`, `fontWeight`, `fontSize` та внутрішніх посилань.

### Поради щодо реалізації

- Нормалізуйте всі зображення до одного розміру та у відтінки сірого перед хешуванням і обчисленням SSIM.
- Кешуйте за перцепційним хешем, щоб уникнути повторного обчислення SSIM для повторюваних glyph-ів між партіями.
- Використовуйте високоякісний розмір растера (наприклад, 256–512 px) для кращої дискримінації; за потреби зменшуйте перед SSIM, щоб прискорити.
- Якщо ви використовуєте Pillow для рендерингу TTF-кандидатів, встановіть той самий розмір канвасу і центрируйте glyph; додайте паддінг, щоб уникнути обрізання ascender/descender.

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

## Евристики реконструкції макету/EPUB

- Розриви абзаців: Якщо верх наступного run’s top Y перевищує baseline попереднього рядка на певний поріг (відносно розміру шрифту), починайте новий абзац.
- Вирівнювання: Групуйте за схожим left X для ліво-вирівняних абзаців; виявляйте центровані рядки за симетричними відступами; виявляйте праве вирівнювання за правими краями.
- Стилізація: Зберігайте italic/bold через `fontStyle`/`fontWeight`; варіюйте CSS classes за `fontSize` buckets, щоб апроксимувати headings vs body.
- Посилання: Якщо runs містять link metadata (наприклад, `positionId`), генеруйте anchors і внутрішні hrefs.

## Mitigating SVG anti-scraping path tricks

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Do not rely on path token normalization.
- Avoid stroke rendering; focus on filled solids to sidestep hairline artifacts caused by micro relative moves.
- Keep a stable viewBox per render so that identical shapes rasterize consistently across batches.

## Performance notes

- In practice, books converge to a few hundred unique glyphs (e.g., ~361 including ligatures). Cache SSIM results by perceptual hash.
- After initial discovery, future batches predominantly re-use known hashes; decoding becomes I/O-bound.
- Average SSIM ≈0.95 is a strong signal; consider flagging low-scoring matches for manual review.

## Generalization to other viewers

Any system that:
- Returns positioned glyph runs with request-scoped numeric IDs
- Ships per-request vector glyphs (SVG paths or subset fonts)
- Caps pages per request to prevent bulk export

…can be handled with the same normalization:
- Rasterize per-request shapes → perceptual hash → shape ID
- Atlas of candidate glyphs/ligatures per font variant
- SSIM (or similar perceptual metric) to assign characters
- Reconstruct layout from run rectangles/styles

## Minimal acquisition example (sketch)

Use your browser’s DevTools to capture the exact headers, cookies and tokens used by the reader when requesting `/renderer/render`. Then replicate those from a script or curl. Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Налаштуйте параметризацію (book ASIN, page window, viewport) відповідно до запитів читача. Очікуйте обмеження до 5 сторінок за один запит.

## Досяжні результати

- Стиснути понад 100 випадкових абеток у єдиний простір гліфів за допомогою perceptual hashing
- 100% відображення унікальних гліфів зі середнім SSIM ≈0.95, коли атласи включають лігатури та варіанти
- Відтворені EPUB/HTML візуально нерозрізненні від оригіналу

## References

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
