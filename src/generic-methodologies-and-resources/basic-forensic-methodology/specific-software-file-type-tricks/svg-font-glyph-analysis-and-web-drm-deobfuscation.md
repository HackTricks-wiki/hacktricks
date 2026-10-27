# Phân tích glyph SVG/font & giải mã obfuscation DRM web (băm raster + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Trang này ghi lại các kỹ thuật thực tế để khôi phục văn bản từ trình đọc web cung cấp các chuỗi glyph được định vị cùng với định nghĩa glyph vector riêng cho từng request (đường dẫn SVG), đồng thời ngẫu nhiên hóa ID glyph theo từng request để ngăn scraping. Ý tưởng cốt lõi là bỏ qua các ID glyph dạng số chỉ có hiệu lực trong phạm vi request và fingerprint hình dạng trực quan bằng cách băm raster, sau đó ánh xạ hình dạng sang ký tự bằng SSIM so với một bảng mẫu font tham chiếu. Cách tiếp cận tương tự có thể áp dụng cho các trình xem có cơ chế bảo vệ tương tự.<sup>[[1]](#references)</sup>

Cảnh báo: Chỉ sử dụng các kỹ thuật này để sao lưu nội dung mà bạn sở hữu hợp pháp và tuân thủ luật cũng như các điều khoản áp dụng.

## Thu thập dữ liệu (ví dụ: Kindle Cloud Reader)

Endpoint được quan sát:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Tài liệu cần có cho mỗi session:<sup>[[1]](#references)</sup>
- Cookie của phiên trình duyệt (đăng nhập Amazon thông thường)
- Token kết xuất từ một lệnh gọi API startReading
- Token phiên ADP bổ sung được renderer sử dụng

Hành vi:<sup>[[1]](#references)</sup>
- Mỗi request, khi được gửi với header và cookie tương đương trình duyệt, sẽ trả về một TAR archive giới hạn ở 5 trang.
- Với một cuốn sách dài, bạn sẽ cần nhiều batch; mỗi batch sử dụng một ánh xạ ID glyph được ngẫu nhiên hóa khác nhau.

Nội dung TAR thường gặp:<sup>[[1]](#references)</sup>
- page_data_0_4.json — các chuỗi văn bản được định vị dưới dạng chuỗi ID glyph (không phải Unicode)
- glyphs.json — định nghĩa đường dẫn SVG cho từng glyph và fontFamily theo từng request
- toc.json — mục lục
- metadata.json — metadata của sách
- location_map.json — ánh xạ vị trí logic→trực quan

Cấu trúc ví dụ của page run:<sup>[[1]](#references)</sup>
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

Ví dụ về mục nhập glyphs.json:<sup>[[1]](#references)</sup>
```json
{
  "24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```

Ghi chú về các thủ thuật path anti-scraping:<sup>[[1]](#references)</sup>
- Path có thể chứa các bước di chuyển tương đối rất nhỏ (ví dụ: `m3,1 m1,6 m-4,-7`), khiến nhiều vector parser và cách lấy mẫu path ngây thơ bị nhầm lẫn.
- Luôn render các path được tô kín hoàn chỉnh bằng một SVG engine đáng tin cậy (ví dụ: CairoSVG), thay vì so sánh sai khác giữa các lệnh/tọa độ.

## Vì sao cách giải mã ngây thơ thất bại

- Thay thế glyph ngẫu nhiên theo từng request: ánh xạ glyph ID→ký tự thay đổi theo từng batch; ID không có ý nghĩa toàn cục.<sup>[[1]](#references)</sup>
- So sánh trực tiếp tọa độ SVG thiếu tin cậy: các hình dạng giống hệt nhau có thể khác về tọa độ số hoặc cách mã hóa lệnh theo từng request.<sup>[[1]](#references)</sup>
- OCR trên các glyph riêng lẻ hoạt động kém (≈50%), nhầm lẫn dấu câu và các glyph trông giống nhau, đồng thời bỏ qua ligature.<sup>[[1]](#references)</sup>

## Pipeline hoạt động: chuẩn hóa và ánh xạ glyph không phụ thuộc request

1) Rasterize glyph SVG theo từng request
- Tạo một tài liệu SVG tối giản cho mỗi glyph bằng `path` được cung cấp và render lên canvas cố định (ví dụ: 512×512) bằng CairoSVG hoặc engine tương đương có thể xử lý các chuỗi path phức tạp.<sup>[[1]](#references)[[2]](#references)</sup>
- Render màu đen trên nền trắng; tránh dùng stroke để loại bỏ các sai khác phụ thuộc vào renderer và khử răng cưa (AA).

2) Perceptual hashing để nhận diện giữa các request
- Tính perceptual hash (ví dụ: pHash bằng `imagehash.phash`) cho mỗi ảnh glyph.<sup>[[3]](#references)</sup>
- Xem hash là ID ổn định: cùng một hình dạng trực quan ở các request khác nhau sẽ có cùng perceptual hash, qua đó vô hiệu hóa các ID ngẫu nhiên.

3) Tạo font atlas tham chiếu
- Tải các font TTF/OTF mục tiêu (ví dụ: Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Render các ký tự A–Z, a–z, 0–9, dấu câu, ký hiệu đặc biệt (gạch ngang em/en, dấu ngoặc kép) và các ligature cụ thể: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Tạo atlas riêng cho từng biến thể font (normal/italic/bold/bold-italic).
- Dùng text shaper phù hợp (HarfBuzz) nếu cần độ chính xác ở cấp glyph cho ligature; rasterize đơn giản bằng Pillow ImageFont cũng có thể đủ nếu render trực tiếp các chuỗi ligature và engine shaping xử lý chúng.

4) So khớp độ tương đồng hình ảnh bằng SSIM
- Với mỗi ảnh glyph chưa biết, tính SSIM (Structural Similarity Index) so với tất cả ảnh ứng viên trong các atlas biến thể font.<sup>[[4]](#references)</sup>
- Gán chuỗi ký tự của kết quả khớp có điểm cao nhất. SSIM xử lý sai khác nhỏ về khử răng cưa, tỷ lệ và tọa độ tốt hơn so với phép so sánh khớp chính xác từng pixel.<sup>[[1]](#references)[[4]](#references)</sup>

5) Xử lý trường hợp biên và tái dựng
- Khi một glyph ánh xạ tới một ligature (nhiều ký tự), hãy mở rộng nó trong quá trình giải mã.<sup>[[1]](#references)</sup>
- Dùng các hình chữ nhật của từng run (trên/trái/phải/dưới) để suy ra ngắt đoạn (chênh lệch Y), căn chỉnh (mẫu X), kiểu chữ và kích thước.<sup>[[1]](#references)</sup>
- Tuần tự hóa thành HTML/EPUB, giữ nguyên `fontStyle`, `fontWeight`, `fontSize` và các liên kết nội bộ.<sup>[[1]](#references)</sup>

### Mẹo triển khai

- Chuẩn hóa tất cả ảnh về cùng kích thước và ảnh xám trước khi hashing và tính SSIM.
- Cache theo perceptual hash để tránh tính lại SSIM cho các glyph lặp lại giữa các batch.
- Dùng kích thước raster chất lượng cao (ví dụ: 256–512 px) để phân biệt tốt hơn; giảm kích thước trước khi tính SSIM nếu cần tăng tốc.
- Nếu dùng Pillow để render các font TTF ứng viên, hãy đặt cùng kích thước canvas và căn giữa glyph; chừa lề để tránh cắt mất phần vươn lên/vươn xuống.

<details>
<summary>Python: chuẩn hóa và so khớp glyph đầu-cuối (raster hash + SSIM)</summary>

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

## Heuristics tái dựng bố cục/EPUB

Báo cáo nguồn sử dụng hình học của run, các trường kiểu dáng và metadata liên kết để giữ nguyên định dạng của tài liệu được tái dựng.<sup>[[1]](#references)</sup>

- Ngắt đoạn: Nếu tọa độ Y trên cùng của run tiếp theo vượt quá baseline của dòng trước một ngưỡng (tương ứng với cỡ font), hãy bắt đầu đoạn mới.<sup>[[1]](#references)</sup>
- Căn chỉnh: Nhóm các đoạn căn trái theo tọa độ X trái tương tự; phát hiện các dòng căn giữa qua lề đối xứng; phát hiện các dòng căn phải qua mép phải.
- Kiểu dáng: Giữ nguyên chữ nghiêng/in đậm qua `fontStyle`/`fontWeight`; thay đổi CSS class theo các nhóm `fontSize` để mô phỏng tiêu đề và phần nội dung.
- Liên kết: Nếu run có metadata liên kết (ví dụ: `positionId`), hãy xuất anchor và href nội bộ.

## Giảm thiểu các thủ thuật đường dẫn SVG chống scraping

- Sử dụng các path có tô kín với `fill-rule: nonzero` và renderer phù hợp (CairoSVG, resvg). Không dựa vào chuẩn hóa token của path.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Tránh render nét viền; tập trung vào các hình khối tô kín để tránh lỗi nét mảnh do các dịch chuyển tương đối nhỏ gây ra.
- Giữ `viewBox` ổn định cho mỗi lần render để các hình dạng giống hệt nhau được rasterize nhất quán giữa các batch.

## Ghi chú về hiệu năng

- Trên thực tế, số glyph duy nhất trong sách thường hội tụ về vài trăm (ví dụ: khoảng 361, tính cả ligature). Cache kết quả SSIM theo perceptual hash.<sup>[[1]](#references)</sup>
- Sau lần phát hiện ban đầu, các batch tiếp theo chủ yếu tái sử dụng hash đã biết; quá trình giải mã trở thành tác vụ bị giới hạn bởi I/O.
- Báo cáo được trích dẫn ghi nhận SSIM trung bình khoảng 0.95; đánh dấu các kết quả khớp có điểm thấp để kiểm tra thủ công.<sup>[[1]](#references)</sup>

## Khái quát hóa cho các trình xem khác

Quy trình Kindle gợi ý rằng các trình xem tương tự có thể áp dụng cùng cách chuẩn hóa nếu chúng:<sup>[[1]](#references)</sup>
- trả về các run glyph có vị trí cùng ID số chỉ có hiệu lực trong từng request
- gửi kèm glyph vector theo từng request (SVG paths hoặc subset fonts)
- giới hạn số trang trong mỗi request

…có thể được xử lý bằng cùng cách chuẩn hóa:
- Rasterize các hình dạng theo từng request → perceptual hash → shape ID
- Tạo atlas các glyph/ligature ứng viên theo từng biến thể font
- Dùng SSIM (hoặc metric cảm nhận tương tự) để gán ký tự
- Tái dựng bố cục từ hình chữ nhật và kiểu dáng của run

## Ví dụ thu thập tối giản (phác thảo)

Dùng DevTools của trình duyệt để ghi lại chính xác các header, cookie và token mà trình đọc sử dụng khi yêu cầu `/renderer/render`. Sau đó mô phỏng các thông tin này bằng script hoặc curl.<sup>[[1]](#references)</sup> Phác thảo ví dụ:

```bash
curl 'https://read.amazon.com/renderer/render' \
  -H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
  -H 'x-adp-session: <ADP_SESSION_TOKEN>' \
  -H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
  -H 'User-Agent: <copy from browser>' \
  -H 'Accept: application/x-tar' \
  --compressed --output batch_000.tar
```

Điều chỉnh tham số (ASIN của sách, phạm vi trang, khung nhìn) để khớp với yêu cầu của người đọc. Giới hạn mỗi yêu cầu là 5 trang.<sup>[[1]](#references)</sup>

## Kết quả có thể đạt được

- Gộp hơn 100 bảng chữ cái được ngẫu nhiên hóa thành một không gian glyph duy nhất bằng perceptual hashing.<sup>[[1]](#references)</sup>
- Trong thử nghiệm 920 trang được trích dẫn, 361 glyph duy nhất đã được khớp (100%) với SSIM trung bình là 0.9527.<sup>[[1]](#references)</sup>
- Báo cáo nguồn mô tả EPUB được tái dựng là gần như không thể phân biệt với bản gốc.<sup>[[1]](#references)</sup>

## References

- [1] [Cách tôi đảo ngược cơ chế làm rối trên Kindle Web của Amazon vì ứng dụng của họ quá tệ (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – Công cụ kết xuất SVG sang PNG](https://cairosvg.org/)
- [3] [imagehash – Băm hình ảnh cảm nhận (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Chỉ số tương đồng cấu trúc (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Thuộc tính tô màu](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – Thư viện kết xuất SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
