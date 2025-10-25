# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, konumlandırılmış glyph run'ları ile birlikte her isteğe özel vektör glyph tanımları (SVG path'leri) gönderen ve scraping'i önlemek için her isteğe göre glyph ID'lerini karıştıran web reader'lardan metin kurtarmaya yönelik pratik teknikleri belgelendirir. Temel fikir, istek kapsamlı sayısal glyph ID'lerini yok sayıp görsel şekilleri raster hashing ile parmak izi haline getirmek, sonra şekilleri referans bir font atlasına karşı SSIM ile karakterlere eşlemektir. İş akışı Kindle Cloud Reader'ın ötesinde, benzer korumaları olan herhangi bir görüntüleyiciye genellenebilir.

Uyarı: Bu teknikleri yalnızca meşru olarak sahip olduğunuz içeriği yedeklemek için ve geçerli kanunlar ile kullanım koşullarına uygun şekilde kullanın.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Her oturum için gerekenler:
- Tarayıcı oturum çerezleri (normal Amazon girişi)
- startReading API çağrısından alınan rendering token'ı
- renderer tarafından kullanılan ek ADP oturum token'ı

Davranış:
- Her istek, tarayıcıyla eşdeğer header'lar ve çerezlerle gönderildiğinde, 5 sayfayla sınırlı bir TAR arşivi döner.
- Uzun bir kitap için birçok batch gereklidir; her batch glyph ID'lerinin farklı bir rastgele eşlemesini kullanır.

Tipik TAR içeriği:
- page_data_0_4.json — konumlandırılmış metin run'ları (glyph ID dizileri, Unicode değil)
- glyphs.json — her istek için her glyph ve fontFamily'e ait SVG path tanımları
- toc.json — içindekiler
- metadata.json — kitap metadata'sı
- location_map.json — mantıksal→görsel pozisyon eşlemeleri

Örnek sayfa run yapısı:
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
Örnek glyphs.json girdisi:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notes on anti-scraping path tricks:
- Paths may include micro relative moves (e.g., `m3,1 m1,6 m-4,-7`) that confuse many vector parsers and naïve path sampling.
- Always render filled complete paths with a robust SVG engine (e.g., CairoSVG) instead of doing command/coordinate differencing.

## Neden naif çözümleme başarısız olur

- İsteğe özgü rastgeleleştirilmiş glyph ikamesi: glyph ID→character mapping her partide değişir; ID'ler küresel olarak anlamsızdır.
- Doğrudan SVG koordinat karşılaştırması kırılgandır: aynı şekiller isteğe göre sayısal koordinatlar veya komut kodlaması bakımından farklılık gösterebilir.
- İzole glyph'ler üzerinde OCR düşük performans verir (≈%50), noktalama işaretlerini ve benzer görünen glyph'leri karıştırır ve ligatürleri yok sayar.

## Çalışan pipeline: istekten bağımsız glyph normalizasyonu ve eşleme

1) İstek başına SVG glyph'lerini rasterleştirme
- Sağlanan `path` ile her glyph için minimal bir SVG belgesi oluşturun ve karmaşık path dizilerini işleyebilen CairoSVG veya eşdeğeri bir motor kullanarak sabit bir tuvala (ör. 512×512) render edin.
- Dolgu olarak siyah üzerine beyaz render edin; renderer- ve AA-bağımlı artefaktları ortadan kaldırmak için stroke'lardan kaçının.

2) İstekler arası kimlik için algısal hashing
- Her glyph görüntüsünün bir algısal hash'ini (ör. `imagehash.phash` ile pHash) hesaplayın.
- Hash'i sabit bir ID gibi ele alın: istekler arasında aynı görsel şekil aynı algısal hash'e düşer ve rastgeleleştirilmiş ID'leri etkisizleştirir.

3) Referans font atlası oluşturma
- Hedef TTF/OTF fontlarını indirin (ör. Bookerly normal/italic/bold/bold-italic).
- A–Z, a–z, 0–9, noktalama işaretleri, özel işaretler (em/en dashes, quotes) ve açık ligatürler için adayları render edin: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Her font varyantı (normal/italic/bold/bold-italic) için ayrı atlaslar tutun.
- Ligatürler için glyph düzeyinde sadakat istiyorsanız uygun bir text shaper (HarfBuzz) kullanın; ligatür dizelerini doğrudan render edip shaping motoru bunları çözdüğü sürece Pillow ImageFont ile basit rasterleştirme yeterli olabilir.

4) SSIM ile görsel benzerlik eşlemesi
- Her bilinmeyen glyph görüntüsü için tüm font varyantı atlaslarındaki tüm aday görüntülere karşı SSIM (Structural Similarity Index) hesaplayın.
- En iyi skoru alan eşleşmenin karakter dizisini atayın. SSIM, küçük antialiasing, ölçek ve koordinat farklılıklarına piksele-tam karşılaştırmalardan daha iyi tolerans gösterir.

5) Kenar durumları ve yeniden yapılandırma
- Bir glyph bir ligatüre (çok karakterli) eşlendiğinde, dekodlama sırasında genişletin.
- Paragraf kırılmalarını (Y deltas), hizalamayı (X desenleri), stil ve boyutları çıkarmak için run dikdörtgenlerini (top/left/right/bottom) kullanın.
- `fontStyle`, `fontWeight`, `fontSize` ve dahili bağlantıları koruyarak HTML/EPUB olarak serileştirin.

### Uygulama ipuçları

- Hash ve SSIM öncesi tüm görüntüleri aynı boyuta ve gri tonlamaya normalize edin.
- Tekrarlanan glyph'ler için SSIM'i yeniden hesaplamaktan kaçınmak adına algısal hash'e göre önbelleğe alın.
- Daha iyi ayrım için yüksek kaliteli bir raster boyutu kullanın (ör. 256–512 px); hızlandırmak için gerekirse SSIM öncesi küçültün.
- TTF adaylarını render etmek için Pillow kullanıyorsanız, aynı tuval boyutunu ayarlayın ve glyph'i ortalayın; yükselenleri/alçalanları kırpmamak için dolgu bırakın.

<details>
<summary>Python: uçtan uca glyph normalizasyonu ve eşleştirme (raster hash + SSIM)</summary>
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

## Yerleşim/EPUB yeniden yapılandırma heuristikleri

- Paragraph breaks: Bir sonraki run’ın üst Y değeri, önceki satırın baseline’ını yazı tipi boyutuna göre ayarlanmış bir eşik kadar aşıyorsa yeni bir paragrafa başla.
- Alignment: Sol hizalı paragraflar için benzer left X değerlerine göre grupla; ortalanmış satırları simetrik margin’lerle tespit et; sağa hizalıları right edge’lere göre belirle.
- Styling: İtalik/kalın stilleri `fontStyle`/`fontWeight` ile koru; başlık ile gövdeyi yaklaşık olarak ayırt etmek için `fontSize` bucket’larına göre CSS sınıflarını değiştir.
- Links: Eğer run’lar link metadata’sı içeriyorsa (ör. `positionId`), anchor’lar ve dahili href’ler üret.

## Mitigating SVG anti-scraping path tricks

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Do not rely on path token normalization.
- Stroke render etmeyin; mikro göreli hareketlerin neden olduğu ince çizgi artefaktlarını aşmak için dolu yüzeylere odaklanın.
- Her render için stabil bir viewBox tutun ki aynı şekiller batch’ler arasında tutarlı şekilde rasterize edilsin.

## Performance notes

- Pratikte, kitaplar birkaç yüz benzersiz glife yakınsar (ör. ligatures dahil ~361). SSIM sonuçlarını perceptual hash ile önbelleğe alın.
- İlk keşiften sonra, sonraki batch’ler ağırlıklı olarak önceden bilinen hash’leri yeniden kullanır; decoding I/O-bound hale gelir.
- Ortalama SSIM ≈0.95 güçlü bir işarettir; düşük puanlı eşleşmeleri manuel inceleme için işaretlemeyi düşünün.

## Generalization to other viewers

Aşağıdaki özelliklere sahip herhangi bir sistem:
- İstek kapsamlı sayısal ID’lerle pozisyonlanmış glyph run’ları döndüren
- İstek başına vektör glyph’leri (SVG path’ler veya subset fontlar) gönderen
- Toplu dışa aktarımları önlemek için istekte sayfa sayısını sınırlayan

…aynı normalizasyon ile ele alınabilir:
- İstek başına şekilleri rasterize et → perceptual hash → shape ID
- Font varyantı başına aday glifler/ligatures atlas’ı
- Karakter ataması için SSIM (veya benzeri bir perceptual metrik)
- Run dikdörtgenleri/stillerinden yerleşimi yeniden inşa et

## Minimal acquisition example (sketch)

Tarayıcınızın DevTools’unu kullanarak okuyucunun `/renderer/render` isteği yaparken kullandığı tam header’ları, cookie’leri ve token’ları yakalayın. Sonra bunları bir script veya curl ile yeniden oluşturun. Örnek taslak:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Parametreleştirmeyi (book ASIN, page window, viewport) okuyucunun isteklerine göre ayarlayın. İstek başına 5 sayfa sınırı bekleyin.

## Elde edilebilecek sonuçlar

- Perceptual hashing ile 100+ rastgeleleştirilmiş alfabeyi tek bir glyph alanına sıkıştırma
- Atlases ligatures ve variants içerdiğinde benzersiz glyph'lerin %100 eşlemesi; ortalama SSIM ~0.95
- Yeniden oluşturulan EPUB/HTML görsel olarak orijinalinden ayırt edilemez

## References

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
