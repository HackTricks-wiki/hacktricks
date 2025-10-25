# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Esta página documenta técnicas práticas para recuperar texto de web readers que entregam positioned glyph runs além de definições vetoriais de glyph por requisição (SVG paths), e que randomizam glyph IDs por requisição para impedir scraping. A ideia central é ignorar os glyph IDs numéricos com escopo de requisição e fingerprintar as formas visuais via raster hashing, então mapear formas para caracteres usando SSIM contra um atlas de fontes de referência. O fluxo de trabalho generaliza além do Kindle Cloud Reader para qualquer viewer com proteções semelhantes.

Aviso: Use estas técnicas apenas para fazer backup de conteúdo que você possui legitimamente e em conformidade com leis e termos aplicáveis.

## Aquisição (exemplo: Kindle Cloud Reader)

Endpoint observado:
- https://read.amazon.com/renderer/render

Materiais necessários por sessão:
- Cookies de sessão do navegador (login normal da Amazon)
- Rendering token de uma startReading API call
- Token de sessão ADP adicional usado pelo renderer

Comportamento:
- Cada requisição, quando enviada com headers e cookies equivalentes aos do navegador, retorna um arquivo TAR limitado a 5 páginas.
- Para um livro longo você precisará de muitos batches; cada batch usa um mapeamento randomizado diferente de glyph IDs.

Conteúdo típico do TAR:
- page_data_0_4.json — positioned text runs as sequences of glyph IDs (not Unicode)
- glyphs.json — per-request SVG path definitions for each glyph and fontFamily
- toc.json — índice
- metadata.json — metadados do livro
- location_map.json — mapeamentos de posição lógico→visual

Exemplo de estrutura de page run:
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
Exemplo de entrada glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notas sobre truques com paths anti-scraping:
- Paths podem incluir micro movimentos relativos (e.g., `m3,1 m1,6 m-4,-7`) que confundem muitos parsers de vetores e amostragem ingênua de path.
- Sempre renderize paths completos preenchidos com um engine SVG robusto (e.g., CairoSVG) em vez de fazer diferenciação por comando/coordenação.

## Por que decodificação ingênua falha

- Substituição de glifos randomizada por solicitação: o mapeamento glyph ID→character muda a cada lote; IDs não têm significado globalmente.
- Comparação direta de coordenadas SVG é frágil: formas idênticas podem diferir nas coordenadas numéricas ou na codificação de comandos por solicitação.
- OCR em glifos isolados tem desempenho ruim (≈50%), confunde pontuação e glifos parecidos, e ignora ligaturas.

## Pipeline de trabalho: normalização e mapeamento de glifos independente da solicitação

1) Rasterizar glifos SVG por solicitação
- Monte um documento SVG mínimo por glifo com o `path` fornecido e renderize em uma tela fixa (e.g., 512×512) usando CairoSVG ou um engine equivalente que lide com sequências de path complicadas.
- Renderize preenchido em preto sobre branco; evite strokes para eliminar artefatos dependentes do renderer e de AA.

2) Hash perceptual para identidade entre solicitações
- Calcule um hash perceptual (e.g., pHash via `imagehash.phash`) de cada imagem de glifo.
- Trate o hash como um ID estável: a mesma forma visual entre solicitações colapsa para o mesmo hash perceptual, derrotando IDs randomizados.

3) Geração de atlas de fontes de referência
- Baixe as fontes TTF/OTF alvo (e.g., Bookerly normal/italic/bold/bold-italic).
- Renderize candidatos para A–Z, a–z, 0–9, pontuação, marcas especiais (em/en dashes, quotes), e ligaturas explícitas: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantenha atlas separados por variante de fonte (normal/italic/bold/bold-italic).
- Use um text shaper adequado (HarfBuzz) se quiser fidelidade ao nível de glifo para ligaturas; rasterização simples via Pillow ImageFont pode ser suficiente se você renderizar as strings de ligatura diretamente e o engine de shaping as resolver.

4) Casamento por similaridade visual com SSIM
- Para cada imagem de glifo desconhecida, calcule SSIM (Structural Similarity Index) contra todas as imagens candidatas em todos os atlas de variantes de fonte.
- Atribua a string de caractere da melhor correspondência. SSIM absorve pequenas diferenças de antialiasing, escala e coordenadas melhor que comparações exatas por pixel.

5) Tratamento de bordas e reconstrução
- Quando um glifo mapeia para uma ligatura (multi-char), expanda-a durante a decodificação.
- Use run rectangles (top/left/right/bottom) para inferir quebras de parágrafo (deltas Y), alinhamento (padrões X), estilo e tamanhos.
- Serialize para HTML/EPUB preservando `fontStyle`, `fontWeight`, `fontSize`, e links internos.

### Dicas de implementação

- Normalize todas as imagens para o mesmo tamanho e escala de cinza antes do hashing e do SSIM.
- Cacheie por hash perceptual para evitar recomputar SSIM para glifos repetidos entre lotes.
- Use um tamanho de raster de alta qualidade (e.g., 256–512 px) para melhor discriminação; reduza a escala conforme necessário antes do SSIM para acelerar.
- Se usar Pillow para renderizar candidatos TTF, defina o mesmo tamanho de canvas e centralize o glifo; adicione padding para evitar recorte de ascendentes/descendentes.

<details>
<summary>Python: normalização e correspondência de glifos de ponta a ponta (raster hash + SSIM)</summary>
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

## Heurísticas de reconstrução de layout/EPUB

- Quebras de parágrafo: Se o top Y do run seguinte exceder a linha de base da linha anterior por um limiar (relativo ao tamanho da fonte), inicie um novo parágrafo.
- Alinhamento: Agrupe por valores similares de left X para parágrafos alinhados à esquerda; detecte linhas centralizadas por margens simétricas; detecte parágrafos alinhados à direita pelas bordas à direita.
- Estilização: Preserve italic/bold via `fontStyle`/`fontWeight`; varie classes CSS por faixas de `fontSize` para aproximar títulos do corpo.
- Links: Se runs incluírem metadados de link (ex.: `positionId`), emita anchors e internal hrefs.

## Mitigando truques anti-scraping de path em SVG

- Use caminhos preenchidos com `fill-rule: nonzero` e um renderizador adequado (CairoSVG, resvg). Não dependa da normalização dos tokens do path.
- Evite renderização de stroke; concentre-se em sólidos preenchidos para contornar artefatos hairline causados por micro-movimentos relativos.
- Mantenha um viewBox estável por render para que formas idênticas rasterizem consistentemente entre lotes.

## Notas de desempenho

- Na prática, livros convergem para algumas centenas de glifos únicos (por exemplo, ~361 incluindo ligaduras). Cacheie resultados de SSIM por perceptual hash.
- Após a descoberta inicial, lotes futuros predominantemente reutilizam hashes conhecidos; a decodificação torna-se limitada por I/O.
- SSIM médio ≈0.95 é um sinal forte; considere sinalizar correspondências com baixa pontuação para revisão manual.

## Generalização para outros viewers

Qualquer sistema que:
- Retorne positioned glyph runs com IDs numéricos com escopo por requisição
- Forneça glifos vetoriais por requisição (SVG paths ou subset fonts)
- Limite páginas por requisição para prevenir exportação em massa

…pode ser tratado com a mesma normalização:
- Rasterize formas por requisição → perceptual hash → shape ID
- Atlas de glifos/ligaduras candidatas por variante de fonte
- SSIM (ou métrica perceptual similar) para atribuir caracteres
- Reconstruir layout a partir dos retângulos/estilos dos runs

## Exemplo mínimo de aquisição (esboço)

Use as DevTools do seu navegador para capturar os headers, cookies e tokens exatos usados pelo leitor ao solicitar `/renderer/render`. Em seguida, replique-os a partir de um script ou curl. Esboço de exemplo:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Ajuste a parametrização (book ASIN, page window, viewport) para corresponder às solicitações do leitor. Espere um limite de 5 páginas por solicitação.

## Resultados alcançáveis

- Colapsar 100+ alfabetos randomizados em um único espaço de glyphs via perceptual hashing
- Mapeamento 100% dos glyphs únicos com SSIM médio ~0.95 quando os atlases incluem ligatures e variantes
- EPUB/HTML reconstruído visualmente indistinguível do original

## Referências

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
