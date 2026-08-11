# Аналіз гліфів SVG/шрифтів і деобфускація Web DRM (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

На цій сторінці описано практичні техніки відновлення тексту з web-рідерів, які передають позиціоновані послідовності гліфів разом із векторними визначеннями гліфів для кожного запиту (SVG paths) і рандомізують ID гліфів для кожного запиту, щоб запобігати scraping. Основна ідея полягає в тому, щоб ігнорувати числові ID гліфів, прив’язані до конкретного запиту, і ідентифікувати візуальні форми за допомогою raster hashing, а потім зіставляти форми із символами через SSIM, використовуючи атлас еталонного шрифту. Такий самий підхід може узагальнюватися на viewers із подібними засобами захисту.<sup>[[1]](#references)</sup>

Попередження: використовуйте ці техніки лише для резервного копіювання контенту, яким ви законно володієте, і відповідно до чинного законодавства та умов використання.

## Отримання (приклад: Kindle Cloud Reader)

Виявлений endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Необхідні матеріали для кожної сесії:<sup>[[1]](#references)</sup>
- Cookies браузерної сесії (звичайний Amazon login)
- Rendering token із виклику startReading API
- Додатковий ADP session token, який використовує renderer

Поведінка:<sup>[[1]](#references)</sup>
- Кожен запит, надісланий із headers і cookies, еквівалентними браузерним, повертає TAR archive, обмежений 5 сторінками.
- Для довгої книги знадобиться багато batch-ів; кожен batch використовує інше рандомізоване зіставлення ID гліфів.

Типовий вміст TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — позиціоновані текстові послідовності як послідовності ID гліфів (не Unicode)
- glyphs.json — визначення SVG path для кожного гліфа та fontFamily у межах конкретного запиту
- toc.json — зміст
- metadata.json — metadata книги
- location_map.json — зіставлення логічних→візуальних позицій

Приклад структури послідовності сторінки:<sup>[[1]](#references)</sup>
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
Нотатки щодо трюків із шляхами для anti-scraping:<sup>[[1]](#references)</sup>
- Шляхи можуть містити мікрорухи відносно початкової точки (наприклад, `m3,1 m1,6 m-4,-7`), які збивають з пантелику багато векторних парсерів і наївне семплювання шляхів.
- Завжди візуалізуйте повні залиті шляхи за допомогою надійного SVG-рушія (наприклад, CairoSVG), замість виконання диференціювання команд/координат.

## Чому наївне декодування не працює

- Рандомізована підміна гліфів для кожного запиту: відповідність ID гліфа→символ змінюється в кожній пакетній вибірці; ID не мають глобального значення.<sup>[[1]](#references)</sup>
- Пряме порівняння координат SVG є ненадійним: ідентичні форми можуть відрізнятися числовими координатами або кодуванням команд у кожному запиті.<sup>[[1]](#references)</sup>
- OCR ізольованих гліфів працює погано (≈50%), плутає пунктуацію та схожі гліфи й ігнорує лігатури.<sup>[[1]](#references)</sup>

## Робочий pipeline: нормалізація та зіставлення гліфів, незалежні від запиту

1) Растеризація SVG-гліфів для кожного запиту
- Створіть мінімальний SVG-документ для кожного гліфа з наданим `path` і візуалізуйте його на фіксованому полотні (наприклад, 512×512) за допомогою CairoSVG або еквівалентного рушія, який обробляє складні послідовності шляхів.<sup>[[1]](#references)[[2]](#references)</sup>
- Візуалізуйте чорну заливку на білому тлі; уникайте обведень, щоб усунути артефакти, залежні від рушія та AA.

2) Перцептивне хешування для ідентифікації між запитами
- Обчисліть перцептивний хеш (наприклад, pHash через `imagehash.phash`) для кожного зображення гліфа.<sup>[[3]](#references)</sup>
- Використовуйте хеш як стабільний ID: однакова візуальна форма в різних запитах зводиться до однакового перцептивного хешу, нівелюючи рандомізовані ID.

3) Створення атласу референсних шрифтів
- Завантажте цільові шрифти TTF/OTF (наприклад, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Візуалізуйте кандидати для A–Z, a–z, 0–9, пунктуації, спеціальних символів (тире em/en, лапки) та явних лігатур: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Зберігайте окремі атласи для кожного варіанта шрифту (normal/italic/bold/bold-italic).
- Використовуйте належний text shaper (HarfBuzz), якщо потрібна точність на рівні гліфів для лігатур; простої растеризації через Pillow ImageFont може бути достатньо, якщо безпосередньо візуалізувати рядки лігатур, а рушій формування коректно їх обробляє.

4) Зіставлення за візуальною схожістю за допомогою SSIM
- Для кожного невідомого зображення гліфа обчисліть SSIM (Structural Similarity Index) порівняно з усіма зображеннями-кандидатами в усіх атласах варіантів шрифту.<sup>[[4]](#references)</sup>
- Призначте рядок символів із найкращим результатом. SSIM краще за порівняння піксель-у-піксель поглинає невеликі відмінності згладжування, масштабу та координат.<sup>[[1]](#references)[[4]](#references)</sup>

5) Обробка країв і реконструкція
- Якщо гліф відповідає лігатурі (кільком символам), розгорніть її під час декодування.<sup>[[1]](#references)</sup>
- Використовуйте прямокутники рядків (top/left/right/bottom), щоб визначати розриви абзаців (дельти Y), вирівнювання (шаблони X), стиль і розміри.<sup>[[1]](#references)</sup>
- Серіалізуйте в HTML/EPUB, зберігаючи `fontStyle`, `fontWeight`, `fontSize` і внутрішні посилання.<sup>[[1]](#references)</sup>

### Поради щодо реалізації

- Нормалізуйте всі зображення до однакового розміру та відтінків сірого перед хешуванням і SSIM.
- Кешуйте за перцептивним хешем, щоб не обчислювати SSIM повторно для гліфів, які повторюються в різних пакетах.
- Використовуйте високоякісний розмір растеризації (наприклад, 256–512 px) для кращого розрізнення; за потреби зменшуйте розмір перед SSIM для прискорення.
- Якщо використовуєте Pillow для візуалізації кандидатів TTF, задайте однаковий розмір полотна та відцентруйте гліф; додайте відступи, щоб уникнути обрізання верхніх і нижніх виносних елементів.

<details>
<summary>Python: наскрізна нормалізація та зіставлення гліфів (растровий хеш + SSIM)</summary>
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

У вихідному звіті використовувалися геометрія run, поля стилю та метадані посилань для збереження форматування реконструйованого документа.<sup>[[1]](#references)</sup>

- Розриви абзаців: Якщо верхня координата Y наступного run перевищує baseline попереднього рядка на певний поріг (відносно розміру шрифту), починайте новий абзац.<sup>[[1]](#references)</sup>
- Вирівнювання: Групуйте за близькими лівими координатами X для абзаців із вирівнюванням по лівому краю; визначайте центровані рядки за симетричними полями; визначайте вирівнювання по правому краю за правими межами.
- Стилізація: Зберігайте курсив/жирний шрифт через `fontStyle`/`fontWeight`; змінюйте CSS-класи за діапазонами `fontSize`, щоб приблизно розрізняти заголовки й основний текст.
- Посилання: Якщо runs містять метадані посилань (наприклад, `positionId`), створюйте anchors і внутрішні hrefs.

## Протидія SVG-трюкам проти scraping

- Використовуйте filled paths із `fill-rule: nonzero` і належний renderer (CairoSVG, resvg). Не покладайтеся на нормалізацію токенів path.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Уникайте stroke rendering; зосередьтеся на filled solids, щоб обійти артефакти тонких ліній, спричинені мікропереходами відносного переміщення.
- Використовуйте стабільний viewBox для кожного render, щоб ідентичні форми растеризувалися узгоджено між пакетами.

## Примітки щодо продуктивності

- На практиці books зводяться до кількох сотень унікальних glyphs (наприклад, приблизно 361, включно з ligatures). Кешуйте результати SSIM за perceptual hash.<sup>[[1]](#references)</sup>
- Після початкового виявлення майбутні batches переважно повторно використовують відомі hashes; decoding стає обмеженим операціями I/O.
- У звіті d спостерігалося середнє значення SSIM приблизно 0.95; позначайте matches із низькими балами для ручної перевірки.<sup>[[1]](#references)</sup>

## Узагальнення для інших viewers

Kindle workflow припускає, що подібні viewers можуть підтримувати таку саму нормалізацію, якщо вони:<sup>[[1]](#references)</sup>
- повертають positioned glyph runs із числовими IDs, обмеженими запитом
- передають vector glyphs для кожного запиту (SVG paths або subset fonts)
- обмежують кількість pages на запит

…можуть оброблятися за допомогою тієї самої нормалізації:
- Rasterize shapes для кожного запиту → perceptual hash → shape ID
- Atlas кандидатів glyphs/ligatures для кожного варіанта font
- SSIM (або подібна perceptual metric) для призначення characters
- Реконструюйте layout із прямокутників/styles runs

## Мінімальний приклад отримання даних (ескіз)

Використовуйте DevTools свого браузера, щоб перехопити точні headers, cookies і tokens, які reader використовує під час запиту до `/renderer/render`. Потім відтворіть їх зі script або curl.<sup>[[1]](#references)</sup> Орієнтовна структура:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Налаштуйте параметризацію (ASIN книги, діапазон сторінок, viewport) відповідно до запитів читача. Враховуйте обмеження до 5 сторінок на один запит.<sup>[[1]](#references)</sup>

## Results achievable

- Зведення понад 100 рандомізованих алфавітів до єдиного простору glyph за допомогою perceptual hashing.<sup>[[1]](#references)</sup>
- У тесті на 920 сторінках було зіставлено 361 унікальний glyph (100%) із середнім SSIM 0.9527.<sup>[[1]](#references)</sup>
- У вихідному звіті зазначено, що реконструйований EPUB майже неможливо відрізнити від оригіналу.<sup>[[1]](#references)</sup>

## References

- [1] [Як я здійснив реверс Amazon Kindle Web Obfuscation, бо їхній застосунок був жахливим (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – рендерер SVG у PNG](https://cairosvg.org/)
- [3] [imagehash – перцептивне хешування зображень (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – індекс структурної подібності (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – властивості Fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – бібліотека рендерингу SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
