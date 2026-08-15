# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

На цій сторінці описано практичні методи відновлення тексту з веб-рідерів, які передають позиціоновані glyph runs разом із векторними визначеннями glyph для кожного запиту (SVG paths) і рандомізують ID glyph для запобігання scraping. Основна ідея полягає в тому, щоб ігнорувати числові ID glyph, прив'язані до конкретного запиту, і ідентифікувати візуальні форми за допомогою raster hashing, а потім зіставляти форми з символами через SSIM, порівнюючи їх із reference font atlas. Цей самий підхід може узагальнюватися на viewer із подібними засобами захисту.<sup>[[1]](#references)</sup>

Попередження: використовуйте ці методи лише для резервного копіювання контенту, яким ви законно володієте, і відповідно до чинного законодавства та умов використання.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Required materials per session:<sup>[[1]](#references)</sup>
- Cookies сесії browser (звичайний Amazon login)
- Rendering token з виклику startReading API
- Додатковий ADP session token, який використовує renderer

Behavior:<sup>[[1]](#references)</sup>
- Кожен запит, надісланий із browser-equivalent headers і cookies, повертає TAR archive, обмежений 5 сторінками.
- Для довгої книги знадобиться багато batches; кожен batch використовує інше рандомізоване mapping glyph IDs.

Typical TAR contents:<sup>[[1]](#references)</sup>
- page_data_0_4.json — позиціоновані text runs як послідовності glyph IDs (не Unicode)
- glyphs.json — SVG path definitions для кожного glyph і fontFamily, специфічні для запиту
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
Приклад запису glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Нотатки щодо tricks із шляхами для обходу anti-scraping:<sup>[[1]](#references)</sup>
- Шляхи можуть містити мікрорухи відносно поточної позиції (наприклад, `m3,1 m1,6 m-4,-7`), які збивають з пантелику багато vector parser'ів і наївне семплювання шляхів.
- Завжди рендеріть повні зафарбовані шляхи за допомогою надійного SVG engine (наприклад, CairoSVG), замість виконання диференціювання команд/координат.

## Чому наївне декодування не працює

- Рандомізована підстановка glyph для кожного запиту: відповідність glyph ID→символ змінюється в кожній batch; ID не мають глобального значення.<sup>[[1]](#references)</sup>
- Пряме порівняння SVG-координат є ненадійним: ідентичні форми можуть відрізнятися числовими координатами або кодуванням команд у кожному запиті.<sup>[[1]](#references)</sup>
- OCR для ізольованих glyph працює погано (≈50%), плутає пунктуацію та схожі glyph і не враховує ligature.<sup>[[1]](#references)</sup>

## Робочий pipeline: нормалізація та mapping glyph, незалежні від запиту

1) Растеризація SVG glyph для кожного запиту
- Створіть мінімальний SVG-документ для кожного glyph із наданим `path` і відрендеріть його на фіксованому canvas (наприклад, 512×512), використовуючи CairoSVG або еквівалентний engine, який обробляє складні послідовності шляхів.<sup>[[1]](#references)[[2]](#references)</sup>
- Рендеріть чорну заливку на білому тлі; уникайте обводок, щоб усунути артефакти, залежні від renderer та AA.

2) Perceptual hashing для ідентифікації між запитами
- Обчисліть perceptual hash (наприклад, pHash через `imagehash.phash`) для кожного зображення glyph.<sup>[[3]](#references)</sup>
- Використовуйте hash як стабільний ID: однакова візуальна форма в різних запитах зводиться до однакового perceptual hash, що нівелює рандомізовані ID.

3) Створення reference font atlas
- Завантажте цільові TTF/OTF fonts (наприклад, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Відрендеріть candidates для A–Z, a–z, 0–9, пунктуації, спеціальних знаків (em/en dash, лапки) та явних ligature: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Зберігайте окремі atlas для кожного font variant (normal/italic/bold/bold-italic).
- Використовуйте належний text shaper (HarfBuzz), якщо потрібна точність на рівні glyph для ligature; простої растеризації через Pillow ImageFont може бути достатньо, якщо безпосередньо рендерити рядки ligature і shaping engine коректно їх обробляє.

4) Visual similarity matching за допомогою SSIM
- Для кожного невідомого зображення glyph обчисліть SSIM (Structural Similarity Index) щодо всіх candidate images у всіх font variant atlas.<sup>[[4]](#references)</sup>
- Призначте рядок символів із match із найкращим результатом. SSIM краще за pixel-exact comparisons враховує невеликі відмінності в antialiasing, масштабі та координатах.<sup>[[1]](#references)[[4]](#references)</sup>

5) Обробка edge cases і реконструкція
- Якщо glyph відповідає ligature (кільком символам), розгорніть її під час декодування.<sup>[[1]](#references)</sup>
- Використовуйте run rectangles (top/left/right/bottom), щоб визначати розриви абзаців (дельти Y), вирівнювання (патерни X), стиль і розміри.<sup>[[1]](#references)</sup>
- Серіалізуйте в HTML/EPUB, зберігаючи `fontStyle`, `fontWeight`, `fontSize` та internal links.<sup>[[1]](#references)</sup>

### Поради щодо реалізації

- Нормалізуйте всі зображення до однакового розміру та grayscale перед hashing і SSIM.
- Кешуйте за perceptual hash, щоб не обчислювати SSIM повторно для glyph, які повторюються в різних batch.
- Використовуйте високоякісний розмір растру (наприклад, 256–512 px) для кращого розрізнення; за потреби зменшуйте його перед SSIM для прискорення.
- Якщо використовуєте Pillow для рендерингу TTF candidates, задайте однаковий розмір canvas і центруйте glyph; додайте відступи, щоб уникнути обрізання ascenders/descenders.

<details>
<summary>Python: наскрізна нормалізація та matching glyph (raster hash + SSIM)</summary>
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

## Евристики реконструкції Layout/EPUB

У вихідному звіті для збереження форматування реконструйованого документа використовувалися геометрія run, поля стилю та метадані посилань.<sup>[[1]](#references)</sup>

- Розриви абзаців: Якщо верхня координата Y наступного run перевищує baseline попереднього рядка на порогове значення (відносно розміру шрифту), починайте новий абзац.<sup>[[1]](#references)</sup>
- Вирівнювання: Групуйте абзаци з вирівнюванням ліворуч за подібною лівою координатою X; визначайте центровані рядки за симетричними полями; визначайте вирівнювання праворуч за правими краями.
- Стилізація: Зберігайте курсив/жирний шрифт через `fontStyle`/`fontWeight`; змінюйте CSS-класи залежно від діапазонів `fontSize`, щоб приблизно розрізняти заголовки й основний текст.
- Посилання: Якщо run містять метадані посилань (наприклад, `positionId`), створюйте anchors і внутрішні href.

## Усунення хитрощів SVG anti-scraping із path

- Використовуйте заповнені paths із `fill-rule: nonzero` і належний renderer (CairoSVG, resvg). Не покладайтеся на нормалізацію токенів path.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Уникайте rendering обводок; зосередьтеся на заповнених суцільних формах, щоб обійти артефакти тонких ліній, спричинені мікрорухами відносних координат.
- Використовуйте стабільний viewBox для кожного render, щоб ідентичні форми однаково растеризувалися в різних batch.

## Примітки щодо продуктивності

- На практиці книги зводяться до кількох сотень унікальних glyph (наприклад, ~361 разом із ligatures). Кешуйте результати SSIM за perceptual hash.<sup>[[1]](#references)</sup>
- Після початкового виявлення наступні batch переважно повторно використовують відомі hash; decoding стає обмеженим швидкістю I/O.
- У цитованому звіті спостерігалося середнє значення SSIM близько 0.95; позначайте збіги з низьким показником для ручної перевірки.<sup>[[1]](#references)</sup>

## Узагальнення для інших viewers

Workflow Kindle свідчить, що подібні viewers можуть підтримувати таку саму нормалізацію, якщо вони:<sup>[[1]](#references)</sup>
- повертають positioned glyph runs із числовими ID, прив’язаними до request
- передають vector glyphs для кожного request (SVG paths або subset fonts)
- обмежують кількість сторінок на request

…можуть оброблятися за допомогою тієї самої нормалізації:
- Растеризувати форми для кожного request → perceptual hash → shape ID
- Atlas кандидатів glyph/ligatures для кожного варіанта font
- SSIM (або подібна perceptual metric) для призначення символів
- Реконструювати layout із прямокутників run/стилів

## Мінімальний приклад acquisition (sketch)

Використовуйте DevTools браузера, щоб перехопити точні headers, cookies і tokens, які reader використовує під час запиту до `/renderer/render`. Потім відтворіть їх зі script або curl.<sup>[[1]](#references)</sup> Приклад структури:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Налаштуйте параметризацію (ASIN книги, діапазон сторінок, viewport) відповідно до запитів читача. Очікуйте обмеження до 5 сторінок на запит.<sup>[[1]](#references)</sup>

## Досяжні результати

- Згорнути понад 100 рандомізованих алфавітів до єдиного glyph space за допомогою perceptual hashing.<sup>[[1]](#references)</sup>
- У наведеному тесті на 920 сторінках було зіставлено 361 унікальний glyph (100%) із середнім SSIM 0.9527.<sup>[[1]](#references)</sup>
- У вихідному звіті зазначено, що реконструйований EPUB майже не відрізняється від оригіналу.<sup>[[1]](#references)</sup>

## References

- [1] [Як я здійснив reverse engineering веб-обфускації Amazon Kindle, бо їхній застосунок був жахливим (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – рендерер SVG у PNG](https://cairosvg.org/)
- [3] [imagehash – перцептивне хешування зображень (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – індекс структурної подібності (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – властивості fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – бібліотека рендерингу SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
