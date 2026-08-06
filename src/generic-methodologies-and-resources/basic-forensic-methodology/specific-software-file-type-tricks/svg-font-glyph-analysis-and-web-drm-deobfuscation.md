# Аналіз гліфів SVG/шрифтів і деобфускація Web DRM (растрове хешування + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

На цій сторінці описано практичні методи відновлення тексту з вебрідерів, які передають позиціоновані послідовності гліфів разом із векторними визначеннями гліфів для кожного запиту (шляхи SVG) і рандомізують ідентифікатори гліфів для кожного запиту, щоб запобігти scraping. Основна ідея полягає в тому, щоб ігнорувати числові ідентифікатори гліфів, прив'язані до конкретного запиту, і визначати візуальні форми за допомогою растрового хешування, а потім зіставляти форми із символами за допомогою SSIM і еталонного атласу шрифту. Цей workflow можна застосовувати не лише до Kindle Cloud Reader, а й до будь-якого viewer із подібними засобами захисту.<sup>[[1]](#references)</sup>

Попередження: Використовуйте ці методи лише для резервного копіювання контенту, яким ви законно володієте, і відповідно до чинного законодавства та умов використання.

## Отримання (приклад: Kindle Cloud Reader)

Виявлений endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Необхідні матеріали для кожної сесії:
- Cookies браузерної сесії (звичайний вхід до Amazon)
- Rendering token із виклику API startReading
- Додатковий ADP session token, який використовує renderer

Поведінка:
- Кожен запит, надісланий із заголовками та cookies, еквівалентними браузерним, повертає TAR-архів, обмежений 5 сторінками.
- Для довгої книги знадобиться багато batch; кожен batch використовує інше рандомізоване зіставлення ідентифікаторів гліфів.

Типовий вміст TAR:
- page_data_0_4.json — позиціоновані текстові послідовності у вигляді послідовностей ідентифікаторів гліфів (не Unicode)
- glyphs.json — визначення шляхів SVG для кожного гліфа та fontFamily у межах конкретного запиту
- toc.json — зміст
- metadata.json — метадані книги
- location_map.json — зіставлення логічних і візуальних позицій

Приклад структури послідовності гліфів сторінки:
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
Нотатки щодо anti-scraping path tricks:
- Paths можуть містити мікрорухи відносно (наприклад, `m3,1 m1,6 m-4,-7`), які збивають з пантелику багато vector parsers і наївне семплювання paths.
- Завжди рендеріть заповнені повні paths за допомогою надійного SVG engine (наприклад, CairoSVG), замість виконання диференціювання команд/координат.

## Чому наївне декодування не працює

- Рандомізована підміна glyph для кожного запиту: mapping glyph ID→character змінюється в кожній batch; ID не мають глобального значення.<sup>[[1]](#references)</sup>
- Пряме порівняння SVG coordinates є ненадійним: ідентичні shapes можуть відрізнятися числовими координатами або кодуванням команд у кожному запиті.
- OCR для ізольованих glyphs працює погано (≈50%), плутає punctuation і схожі glyphs та ігнорує ligatures.

## Робочий pipeline: request-agnostic нормалізація та mapping glyph

1) Rasterize SVG glyphs для кожного запиту
- Створіть мінімальний SVG document для кожного glyph із наданими `path` і відрендеріть його на фіксованому canvas (наприклад, 512×512), використовуючи CairoSVG або еквівалентний engine, який обробляє складні послідовності paths.<sup>[[1]](#references)[[2]](#references)</sup>
- Рендеріть чорне заповнення на білому тлі; уникайте strokes, щоб усунути артефакти, залежні від renderer і AA.

2) Perceptual hashing для cross-request identity
- Обчисліть perceptual hash (наприклад, pHash через `imagehash.phash`) для кожного glyph image.<sup>[[3]](#references)</sup>
- Розглядайте hash як стабільний ID: одна й та сама visual shape у різних запитах зводиться до того самого perceptual hash, нейтралізуючи randomized IDs.

3) Створення reference font atlas
- Завантажте цільові TTF/OTF fonts (наприклад, Bookerly normal/italic/bold/bold-italic).
- Відрендеріть candidates для A–Z, a–z, 0–9, punctuation, special marks (тире em/en, quotes) та явних ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Підтримуйте окремі atlases для кожного font variant (normal/italic/bold/bold-italic).
- Використовуйте належний text shaper (HarfBuzz), якщо потрібна glyph-level fidelity для ligatures; простого rasterization через Pillow ImageFont може бути достатньо, якщо рендеріти рядки ligatures безпосередньо, а shaping engine коректно їх обробляє.

4) Visual similarity matching за допомогою SSIM
- Для кожного unknown glyph image обчисліть SSIM (Structural Similarity Index) проти всіх candidate images у всіх font variant atlases.<sup>[[4]](#references)</sup>
- Призначте character string найкращого match. SSIM краще за pixel-exact comparisons поглинає невеликі відмінності antialiasing, масштабу та координат.

5) Обробка країв і reconstruction
- Якщо glyph відповідає ligature (кільком символам), розгорніть її під час decoding.
- Використовуйте run rectangles (top/left/right/bottom), щоб визначати розриви абзаців (Y deltas), вирівнювання (X patterns), style і sizes.
- Серіалізуйте в HTML/EPUB, зберігаючи `fontStyle`, `fontWeight`, `fontSize` та internal links.

### Поради щодо implementation

- Нормалізуйте всі images до однакового розміру та grayscale перед hashing і SSIM.
- Кешуйте за perceptual hash, щоб не обчислювати SSIM повторно для glyphs, які повторюються в різних batches.
- Використовуйте high-quality raster size (наприклад, 256–512 px) для кращого розрізнення; за потреби зменшуйте розмір перед SSIM для прискорення.
- Якщо використовуєте Pillow для rendering TTF candidates, задайте однаковий canvas size і розташуйте glyph по центру; додайте padding, щоб уникнути обрізання ascenders/descenders.

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

## Евристики реконструкції Layout/EPUB

- Розриви абзаців: Якщо верхня координата Y наступного run перевищує baseline попереднього рядка на порогове значення (відносно розміру шрифту), починайте новий абзац.<sup>[[1]](#references)</sup>
- Вирівнювання: Групуйте за схожою лівою координатою X для абзаців із вирівнюванням ліворуч; визначайте центровані рядки за симетричними полями; визначайте вирівнювання праворуч за правими краями.
- Стилізація: Зберігайте курсив і жирний шрифт через `fontStyle`/`fontWeight`; змінюйте CSS-класи залежно від діапазонів `fontSize`, щоб приблизно розрізняти заголовки й основний текст.
- Посилання: Якщо runs містять метадані посилань (наприклад, `positionId`), генеруйте anchors і внутрішні hrefs.

## Усунення трюків із SVG path для захисту від scraping

- Використовуйте заповнені paths із `fill-rule: nonzero` і належний renderer (CairoSVG, resvg). Не покладайтеся на нормалізацію path tokens.<sup>[[1]](#references)</sup>
- Уникайте stroke rendering; зосередьтеся на заповнених суцільних формах, щоб обійти артефакти тонких ліній, спричинені мікроскопічними відносними переміщеннями.
- Підтримуйте стабільний viewBox для кожного render, щоб ідентичні форми растеризувалися узгоджено в різних batch.

## Примітки щодо продуктивності

- На практиці книги зводяться до кількох сотень унікальних glyphs (наприклад, приблизно 361, включно з ligatures). Кешуйте результати SSIM за perceptual hash.<sup>[[1]](#references)</sup>
- Після початкового виявлення майбутні batch переважно повторно використовують відомі hashes; decoding стає обмеженим швидкістю I/O.
- Середнє значення SSIM ≈0.95 є сильним сигналом; розгляньте можливість позначати збіги з низькими оцінками для ручної перевірки.

## Узагальнення для інших viewers

Будь-яка система, яка:<sup>[[1]](#references)</sup>
- Повертає positioned glyph runs із numeric IDs, прив’язаними до request
- Надсилає vector glyphs для кожного request (SVG paths або subset fonts)
- Обмежує кількість сторінок у request, щоб запобігти bulk export

…може оброблятися за допомогою тієї самої нормалізації:
- Растеризуйте shapes для кожного request → perceptual hash → shape ID
- Atlas кандидатів glyphs/ligatures для кожного варіанта font
- SSIM (або подібна perceptual metric) для призначення символів
- Реконструюйте layout із rectangles/styles для runs

## Мінімальний приклад отримання даних (ескіз)

Використовуйте DevTools браузера, щоб перехопити точні headers, cookies і tokens, які reader використовує під час запиту до `/renderer/render`. Потім відтворіть їх зі script або curl.<sup>[[1]](#references)</sup> Приблизний outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Налаштуйте параметризацію (ASIN книги, діапазон сторінок, область перегляду) відповідно до запитів читача. Враховуйте обмеження — не більше 5 сторінок на запит.

## Досяжні результати

- Зведення понад 100 рандомізованих алфавітів до єдиного простору гліфів за допомогою перцептивного хешування<sup>[[1]](#references)</sup>
- 100% зіставлення унікальних гліфів із середнім SSIM ~0.95, коли атласи містять лігатури та варіанти
- Відновлений EPUB/HTML, візуально невідмінний від оригіналу

## References

- [1] [Kindle Web DRM: злам рандомізованого SVG-обфускування гліфів за допомогою растрового хешування + SSIM (блог Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – рендерер SVG у PNG](https://cairosvg.org/)
- [3] [imagehash – перцептивне хешування зображень (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – індекс структурної подібності (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
