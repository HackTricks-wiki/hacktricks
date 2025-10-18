# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

This page documents practical techniques to recover text from web readers that ship positioned glyph runs plus per-request vector glyph definitions (SVG paths), and that randomize glyph IDs per request to prevent scraping. The core idea is to ignore request-scoped numeric glyph IDs and fingerprint the visual shapes via raster hashing, then map shapes to characters with SSIM against a reference font atlas. The workflow generalizes beyond Kindle Cloud Reader to any viewer with similar protections.

Warning: Only use these techniques to back up content you legitimately own and in compliance with applicable laws and terms.

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

Example glyphs.json entry:
```json
{
  "24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```

Notes on anti-scraping path tricks:
- Paths may include micro relative moves (e.g., `m3,1 m1,6 m-4,-7`) that confuse many vector parsers and naïve path sampling.
- Always render filled complete paths with a robust SVG engine (e.g., CairoSVG) instead of doing command/coordinate differencing.

## Why naïve decoding fails

- Per-request randomized glyph substitution: glyph ID→character mapping changes every batch; IDs are meaningless globally.
- Direct SVG coordinate comparison is brittle: identical shapes may differ in numeric coordinates or command encoding per request.
- OCR on isolated glyphs performs poorly (≈50%), confuses punctuation and look-alike glyphs, and ignores ligatures.

## Working pipeline: request-agnostic glyph normalization and mapping

1) Rasterize per-request SVG glyphs
- Build a minimal SVG document per glyph with the provided `path` and render to a fixed canvas (e.g., 512×512) using CairoSVG or an equivalent engine that handles tricky path sequences.
- Render filled black on white; avoid strokes to eliminate renderer- and AA-dependent artifacts.

2) Perceptual hashing for cross-request identity
- Compute a perceptual hash (e.g., pHash via `imagehash.phash`) of each glyph image.
- Treat the hash as a stable ID: the same visual shape across requests collapses to the same perceptual hash, defeating randomized IDs.

3) Reference font atlas generation
- Download the target TTF/OTF fonts (e.g., Bookerly normal/italic/bold/bold-italic).
- Render candidates for A–Z, a–z, 0–9, punctuation, special marks (em/en dashes, quotes), and explicit ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Keep separate atlases per font variant (normal/italic/bold/bold-italic).
- Use a proper text shaper (HarfBuzz) if you want glyph-level fidelity for ligatures; simple rasterization via Pillow ImageFont can be sufficient if you render the ligature strings directly and the shaping engine resolves them.

4) Visual similarity matching with SSIM
- For each unknown glyph image, compute SSIM (Structural Similarity Index) against all candidate images across all font variant atlases.
- Assign the character string of the best-scoring match. SSIM absorbs small antialiasing, scale, and coordinate differences better than pixel-exact comparisons.

5) Edge handling and reconstruction
- When a glyph maps to a ligature (multi-char), expand it during decoding.
- Use run rectangles (top/left/right/bottom) to infer paragraph breaks (Y deltas), alignment (X patterns), style, and sizes.
- Serialize to HTML/EPUB preserving `fontStyle`, `fontWeight`, `fontSize`, and internal links.

### Implementation tips

- Normalize all images to the same size and grayscale before hashing and SSIM.
- Cache by perceptual hash to avoid recomputing SSIM for repeated glyphs across batches.
- Use a high-quality raster size (e.g., 256–512 px) for better discrimination; downscale as needed before SSIM to accelerate.
- If using Pillow to render TTF candidates, set the same canvas size and center the glyph; pad to avoid clipping ascenders/descenders.

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

- Paragraph breaks: If the next run’s top Y exceeds the previous line’s baseline by a threshold (relative to font size), start a new paragraph.
- Alignment: Group by similar left X for left-aligned paragraphs; detect centered lines by symmetric margins; detect right-aligned by right edges.
- Styling: Preserve italic/bold via `fontStyle`/`fontWeight`; vary CSS classes by `fontSize` buckets to approximate headings vs body.
- Links: If runs include link metadata (e.g., `positionId`), emit anchors and internal hrefs.

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

Adjust parameterization (book ASIN, page window, viewport) to match the reader’s requests. Expect a 5-page-per-request cap.

## Results achievable

- Collapse 100+ randomized alphabets to a single glyph space via perceptual hashing
- 100% mapping of unique glyphs with average SSIM ~0.95 when atlases include ligatures and variants
- Reconstructed EPUB/HTML visually indistinguishable from the original

## References

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
