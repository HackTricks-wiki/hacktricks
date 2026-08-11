# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, konumlandırılmış glyph dizileri ile istek başına SVG path tanımları içeren ve scraping'i önlemek için glyph ID'lerini her istekte rastgeleleştiren web okuyucularından metin kurtarmaya yönelik pratik teknikleri belgeler. Temel fikir, istek kapsamındaki sayısal glyph ID'lerini yok sayıp görsel şekilleri raster hashing ile fingerprint'lemek, ardından şekilleri bir referans font atlasına karşı SSIM kullanarak karakterlerle eşleştirmektir. Aynı yaklaşım, benzer korumalara sahip görüntüleyiciler için de genellenebilir.<sup>[[1]](#references)</sup>

Uyarı: Bu teknikleri yalnızca yasal olarak sahibi olduğunuz içerikleri yedeklemek ve yürürlükteki yasalara ve şartlara uygun hareket etmek için kullanın.

## Acquisition (example: Kindle Cloud Reader)

Gözlemlenen endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Oturum başına gerekli materyaller:<sup>[[1]](#references)</sup>
- Browser session cookies (normal Amazon login)
- Bir startReading API çağrısından alınan rendering token
- Renderer tarafından kullanılan ek ADP session token

Davranış:<sup>[[1]](#references)</sup>
- Browser eşdeğeri headers ve cookies ile gönderilen her istek, 5 sayfayla sınırlı bir TAR arşivi döndürür.
- Uzun bir kitap için çok sayıda batch gerekir; her batch, glyph ID'leri için farklı bir randomized mapping kullanır.

Tipik TAR içeriği:<sup>[[1]](#references)</sup>
- page_data_0_4.json — glyph ID dizileri olarak konumlandırılmış text runs (Unicode değil)
- glyphs.json — her glyph ve fontFamily için istek başına SVG path tanımları
- toc.json — içindekiler
- metadata.json — kitap metadata'sı
- location_map.json — logical→visual position mappings

Örnek page run yapısı:<sup>[[1]](#references)</sup>
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
Örnek glyphs.json girdisi:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Anti-scraping path hileleri hakkında notlar:<sup>[[1]](#references)</sup>
- Yollar, birçok vector parser'ı ve naif path örneklemesini şaşırtan mikro göreli hareketler (ör. `m3,1 m1,6 m-4,-7`) içerebilir.
- Komut/koordinat farkı almaktansa, doldurulmuş tam path'leri her zaman sağlam bir SVG engine (ör. CairoSVG) ile render edin.

## Naif decoding neden başarısız olur

- İstek başına randomize glyph substitution: glyph ID→character mapping her batch'te değişir; ID'ler global olarak anlamsızdır.<sup>[[1]](#references)</sup>
- Doğrudan SVG koordinat karşılaştırması kırılgandır: aynı şekiller, her istekte farklı sayısal koordinatlara veya command encoding'e sahip olabilir.<sup>[[1]](#references)</sup>
- İzole glyph'lerde OCR kötü performans gösterir (≈%50), punctuation ve benzer görünen glyph'leri karıştırır ve ligature'ları göz ardı eder.<sup>[[1]](#references)</sup>

## Çalışan pipeline: request-agnostic glyph normalization ve mapping

1) İstek başına SVG glyph'lerini rasterize edin
- Sağlanan `path` ile her glyph için minimal bir SVG document oluşturun ve CairoSVG veya zor path sequence'lerini işleyebilen eşdeğer bir engine kullanarak sabit bir canvas'a (ör. 512×512) render edin.<sup>[[1]](#references)[[2]](#references)</sup>
- Siyah dolguyu beyaz zemin üzerine render edin; renderer ve AA kaynaklı artifact'leri ortadan kaldırmak için stroke kullanmaktan kaçının.

2) İstekler arası identity için perceptual hashing
- Her glyph image için bir perceptual hash (ör. `imagehash.phash` üzerinden pHash) hesaplayın.<sup>[[3]](#references)</sup>
- Hash'i stable ID olarak değerlendirin: istekler arasındaki aynı görsel şekil aynı perceptual hash altında birleşir ve randomize ID'leri etkisiz kılar.

3) Reference font atlas oluşturma
- Hedef TTF/OTF font'larını indirin (ör. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- A–Z, a–z, 0–9, punctuation, özel işaretler (em/en dash'ler, tırnak işaretleri) ve açık ligature'lar için adayları render edin: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Her font variant için ayrı atlas'lar tutun (normal/italic/bold/bold-italic).
- Ligature'lar için glyph-level fidelity istiyorsanız uygun bir text shaper (HarfBuzz) kullanın; ligature string'lerini doğrudan render eder ve shaping engine bunları çözerse Pillow ImageFont ile basit rasterization yeterli olabilir.

4) SSIM ile visual similarity matching
- Her unknown glyph image için tüm font variant atlas'larındaki tüm candidate image'lara karşı SSIM (Structural Similarity Index) hesaplayın.<sup>[[4]](#references)</sup>
- En yüksek skorlu eşleşmenin character string'ini atayın. SSIM, pixel-exact karşılaştırmalara kıyasla küçük antialiasing, scale ve koordinat farklılıklarını daha iyi tolere eder.<sup>[[1]](#references)[[4]](#references)</sup>

5) Edge handling ve reconstruction
- Bir glyph bir ligature'a (birden fazla karakter) eşleniyorsa decoding sırasında genişletin.<sup>[[1]](#references)</sup>
- Paragraph break'leri (Y delta'ları), alignment'ı (X pattern'leri), style'ı ve size'ları çıkarsamak için run rectangle'larını (top/left/right/bottom) kullanın.<sup>[[1]](#references)</sup>
- `fontStyle`, `fontWeight`, `fontSize` ve internal link'leri koruyarak HTML/EPUB olarak serialize edin.<sup>[[1]](#references)</sup>

### Implementation tips

- Hashing ve SSIM öncesinde tüm image'ları aynı size ve grayscale formatına normalize edin.
- Batch'ler arasında tekrarlanan glyph'ler için SSIM'i yeniden hesaplamaktan kaçınmak üzere perceptual hash ile cache kullanın.
- Daha iyi ayırt etme için yüksek kaliteli bir raster size (ör. 256–512 px) kullanın; SSIM'i hızlandırmak için gerektiğinde downscale edin.
- TTF adaylarını render etmek için Pillow kullanıyorsanız aynı canvas size'ını ayarlayın ve glyph'i ortalayın; ascender/descender'ların kırpılmasını önlemek için padding ekleyin.

<details>
<summary>Python: uçtan uca glyph normalization ve matching (raster hash + SSIM)</summary>
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

## Layout/EPUB yeniden oluşturma sezgisel yöntemleri

Kaynak rapor, yeniden oluşturulan belgenin biçimlendirmesini korumak için run geometry, style fields ve link metadata kullandı.<sup>[[1]](#references)</sup>

- Paragraph breaks: Sonraki run’ın üst Y değeri, önceki satırın baseline değerini font size’a göre belirlenen bir eşikten fazla aşıyorsa yeni bir paragraf başlatın.<sup>[[1]](#references)</sup>
- Alignment: Sola hizalanmış paragraflar için benzer sol X değerlerine göre gruplandırın; simetrik kenar boşluklarıyla ortalanmış satırları tespit edin; sağ kenarları kullanarak sağa hizalanmış satırları tespit edin.
- Styling: `fontStyle`/`fontWeight` aracılığıyla italic/bold biçimlerini koruyun; heading ile body metinlerini yaklaşık olarak ayırt etmek için `fontSize` bucket’larına göre CSS class’larını değiştirin.
- Links: Run’lar link metadata’sı (ör. `positionId`) içeriyorsa anchor’lar ve internal href’ler oluşturun.

## SVG anti-scraping path hilelerini azaltma

- `fill-rule: nonzero` ile filled path’ler ve uygun bir renderer (CairoSVG, resvg) kullanın. Path token normalization’a güvenmeyin.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Stroke rendering kullanmaktan kaçının; mikro relative move’ların neden olduğu hairline artifact’larını atlamak için filled solid şekillere odaklanın.
- Identical shape’lerin batch’ler arasında tutarlı şekilde rasterize edilmesi için her render için sabit bir viewBox kullanın.

## Performance notları

- Uygulamada kitaplar birkaç yüz unique glyph’e yakınsar (ligature’lar dahil ör. ~361). SSIM sonuçlarını perceptual hash’e göre cache’leyin.<sup>[[1]](#references)</sup>
- İlk discovery işleminden sonra sonraki batch’ler çoğunlukla bilinen hash’leri yeniden kullanır; decoding işlemi I/O-bound hâle gelir.
- d report, yaklaşık 0.95 ortalama SSIM gözlemledi; düşük skorlu eşleşmeleri manual review için işaretleyin.<sup>[[1]](#references)</sup>

## Diğer viewer’lara genelleme

Kindle workflow’u, benzer viewer’ların şu özelliklere sahip olduklarında aynı normalization işlemine uygun olabileceğini gösterir:<sup>[[1]](#references)</sup>
- request-scoped numeric ID’ler içeren positioned glyph run’ları döndürmeleri
- request başına vector glyph’ler (SVG path’leri veya subset font’lar) göndermeleri
- request başına page sayısını sınırlamaları

…aynı normalization ile işlenebilir:
- Request başına shape’leri rasterize edin → perceptual hash → shape ID
- Her font variant için candidate glyph/ligature atlas’ı
- Karakterleri atamak için SSIM (veya benzer bir perceptual metric)
- Run rectangle/style bilgilerinden layout’u yeniden oluşturun

## Minimal acquisition örneği (taslak)

Reader’ın `/renderer/render` isteğinde kullandığı exact header’ları, cookie’leri ve token’ları yakalamak için browser’ınızın DevTools’unu kullanın. Ardından bunları bir script veya curl üzerinden yeniden üretin.<sup>[[1]](#references)</sup> Örnek taslak:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Parametreleri (kitap ASIN'i, sayfa aralığı, viewport) okuyucunun isteklerine uyacak şekilde ayarlayın. İstek başına 5 sayfa sınırı olduğunu varsayın.<sup>[[1]](#references)</sup>

## Elde edilebilecek sonuçlar

- Algısal hashing yoluyla 100'den fazla randomized alphabet'i tek bir glyph space'e indirgeyin.<sup>[[1]](#references)</sup>
- 920 sayfalık testte 361 benzersiz glyph eşleştirildi (%100); ortalama SSIM değeri 0,9527 oldu.<sup>[[1]](#references)</sup>
- Kaynak rapor, yeniden oluşturulan EPUB'un orijinalinden neredeyse ayırt edilemez olduğunu belirtiyor.<sup>[[1]](#references)</sup>

## References

- [1] [Amazon'un Kindle Web Obfuscation'ını, Uygulamaları Berbat Olduğu İçin Nasıl Tersine Mühendislikle Çözdüm (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG'den PNG'ye renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill properties](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG rendering library](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
