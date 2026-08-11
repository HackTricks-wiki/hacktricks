# Análise de Glifos SVG/Font e Desofuscação de Web DRM (Hashing de Rasterização + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Esta página documenta técnicas práticas para recuperar texto de leitores web que enviam sequências de glifos posicionados junto com definições de glifos vetoriais por requisição (caminhos SVG) e que randomizam os IDs dos glifos a cada requisição para impedir scraping. A ideia central é ignorar os IDs numéricos dos glifos específicos da requisição e identificar as formas visuais por meio de raster hashing, mapeando então as formas para caracteres com SSIM, usando um atlas de fonte de referência. A mesma abordagem pode ser aplicável a visualizadores com proteções semelhantes.<sup>[[1]](#references)</sup>

Aviso: Use estas técnicas apenas para fazer backup de conteúdo que você possui legitimamente e em conformidade com as leis e os termos aplicáveis.

## Aquisição (exemplo: Kindle Cloud Reader)

Endpoint observado:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiais necessários por sessão:<sup>[[1]](#references)</sup>
- Cookies da sessão do navegador (login normal da Amazon)
- Token de renderização obtido em uma chamada à API startReading
- Token de sessão ADP adicional usado pelo renderer

Comportamento:<sup>[[1]](#references)</sup>
- Cada requisição, quando enviada com headers e cookies equivalentes aos do navegador, retorna um arquivo TAR limitado a 5 páginas.
- Para um livro longo, serão necessários muitos batches; cada batch usa um mapeamento randomizado diferente dos IDs dos glifos.

Conteúdo típico do TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — sequências de texto posicionadas como sequências de IDs de glifos (não Unicode)
- glyphs.json — definições de caminhos SVG por requisição para cada glifo e fontFamily
- toc.json — sumário
- metadata.json — metadados do livro
- location_map.json — mapeamentos de posição lógica→visual

Estrutura de exemplo de uma sequência de página:<sup>[[1]](#references)</sup>
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
Exemplo de entrada glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notas sobre truques de paths anti-scraping:<sup>[[1]](#references)</sup>
- Os paths podem incluir pequenos movimentos relativos (por exemplo, `m3,1 m1,6 m-4,-7`) que confundem muitos parsers de vetores e o sampling ingênuo de paths.
- Sempre renderize paths preenchidos completos com um mecanismo SVG robusto (por exemplo, CairoSVG), em vez de fazer diferenciação de comandos/coordenadas.

## Por que a decodificação ingênua falha

- Substituição de glyphs randomizada por request: o mapeamento de glyph ID→caractere muda a cada batch; os IDs não têm significado global.<sup>[[1]](#references)</sup>
- A comparação direta de coordenadas SVG é frágil: formas idênticas podem diferir nas coordenadas numéricas ou na codificação dos comandos a cada request.<sup>[[1]](#references)</sup>
- OCR em glyphs isolados tem desempenho ruim (≈50%), confunde pontuação e glyphs visualmente semelhantes, e ignora ligatures.<sup>[[1]](#references)</sup>

## Pipeline funcional: normalização e mapeamento de glyphs independentes de requests

1) Rasterize os glyphs SVG por request
- Construa um documento SVG mínimo por glyph com o `path` fornecido e renderize-o em um canvas fixo (por exemplo, 512×512) usando CairoSVG ou um mecanismo equivalente que lide com sequências de paths complexas.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderize preenchido em preto sobre branco; evite strokes para eliminar artefatos dependentes do renderer e de AA.

2) Perceptual hashing para identidade entre requests
- Calcule um perceptual hash (por exemplo, pHash via `imagehash.phash`) de cada imagem de glyph.<sup>[[3]](#references)</sup>
- Trate o hash como um ID estável: a mesma forma visual em diferentes requests resulta no mesmo perceptual hash, neutralizando IDs randomizados.

3) Geração do atlas da font de referência
- Baixe as fonts TTF/OTF alvo (por exemplo, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Renderize candidatos para A–Z, a–z, 0–9, pontuação, marcas especiais (em/en dashes, aspas) e ligatures explícitas: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantenha atlas separados para cada variante de font (normal/italic/bold/bold-italic).
- Use um text shaper apropriado (HarfBuzz) se quiser fidelidade em nível de glyph para ligatures; a rasterização simples via Pillow ImageFont pode ser suficiente se você renderizar diretamente as strings de ligature e o mecanismo de shaping resolvê-las.

4) Matching de similaridade visual com SSIM
- Para cada imagem de glyph desconhecido, calcule SSIM (Structural Similarity Index) em relação a todas as imagens candidatas em todos os atlas de variantes de font.<sup>[[4]](#references)</sup>
- Atribua a string de caracteres do match com a maior pontuação. O SSIM absorve melhor pequenas diferenças de antialiasing, escala e coordenadas do que comparações pixel a pixel.<sup>[[1]](#references)[[4]](#references)</sup>

5) Tratamento de casos especiais e reconstrução
- Quando um glyph corresponder a uma ligature (multi-char), expanda-o durante a decodificação.<sup>[[1]](#references)</sup>
- Use retângulos de execução (top/left/right/bottom) para inferir quebras de parágrafo (deltas de Y), alinhamento (padrões de X), estilo e tamanhos.<sup>[[1]](#references)</sup>
- Serialize em HTML/EPUB preservando `fontStyle`, `fontWeight`, `fontSize` e links internos.<sup>[[1]](#references)</sup>

### Dicas de implementação

- Normalize todas as imagens para o mesmo tamanho e grayscale antes do hashing e do SSIM.
- Faça cache por perceptual hash para evitar recalcular o SSIM para glyphs repetidos entre batches.
- Use um tamanho de rasterização de alta qualidade (por exemplo, 256–512 px) para melhor discriminação; reduza a escala conforme necessário antes do SSIM para acelerar.
- Se usar Pillow para renderizar candidatos TTF, defina o mesmo tamanho de canvas e centralize o glyph; adicione padding para evitar cortar ascenders/descenders.

<details>
<summary>Python: normalização e matching de glyphs end-to-end (raster hash + SSIM)</summary>
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

O relatório de origem usou a geometria das execuções, campos de estilo e metadados de links para preservar a formatação do documento reconstruído.<sup>[[1]](#references)</sup>

- Quebras de parágrafo: Se o Y superior da próxima execução exceder a linha de base da linha anterior por um limite (relativo ao tamanho da fonte), inicie um novo parágrafo.<sup>[[1]](#references)</sup>
- Alinhamento: Agrupe por X esquerdo semelhante os parágrafos alinhados à esquerda; detecte linhas centralizadas por margens simétricas; detecte alinhamento à direita pelas bordas direitas.
- Estilo: Preserve itálico/negrito usando `fontStyle`/`fontWeight`; varie as classes CSS por intervalos de `fontSize` para aproximar títulos e corpo do texto.
- Links: Se as execuções incluírem metadados de links (por exemplo, `positionId`), emita âncoras e hrefs internos.

## Mitigação de tricks anti-scraping de paths SVG

- Use paths preenchidos com `fill-rule: nonzero` e um renderer apropriado (CairoSVG, resvg). Não dependa da normalização de tokens de paths.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Evite rendering de strokes; concentre-se em sólidos preenchidos para contornar artefatos de hairline causados por micro movimentos relativos.
- Mantenha um viewBox estável por renderização para que formas idênticas sejam rasterizadas de maneira consistente entre batches.

## Observações de performance

- Na prática, os livros convergem para algumas centenas de glyphs únicos (por exemplo, ~361 incluindo ligatures). Armazene os resultados de SSIM em cache por hash perceptual.<sup>[[1]](#references)</sup>
- Após a descoberta inicial, os batches seguintes reutilizam predominantemente hashes conhecidos; a decodificação passa a ser limitada por I/O.
- O relatório d observou um SSIM médio de aproximadamente 0.95; sinalize correspondências com pontuação baixa para revisão manual.<sup>[[1]](#references)</sup>

## Generalização para outros viewers

O workflow do Kindle sugere que viewers semelhantes podem aceitar a mesma normalização quando:<sup>[[1]](#references)</sup>
- retornam glyph runs posicionados com IDs numéricos específicos da requisição
- enviam glyphs vetoriais por requisição (SVG paths ou subset fonts)
- limitam o número de páginas por requisição

…podem ser tratados com a mesma normalização:
- Rasterize as formas por requisição → hash perceptual → ID da forma
- Atlas de glyphs/ligatures candidatos por variante de fonte
- SSIM (ou métrica perceptual semelhante) para atribuir caracteres
- Reconstrua o layout a partir de retângulos/estilos das execuções

## Exemplo mínimo de aquisição (esboço)

Use as DevTools do seu browser para capturar os headers, cookies e tokens exatos usados pelo reader ao solicitar `/renderer/render`. Em seguida, replique-os usando um script ou curl.<sup>[[1]](#references)</sup> Esboço do exemplo:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Ajuste a parameterização (ASIN do livro, janela de páginas, viewport) para corresponder às solicitações do leitor. Espere um limite de 5 páginas por solicitação.<sup>[[1]](#references)</sup>

## Results achievable

- Reduza mais de 100 alfabetos aleatorizados a um único espaço de glifos por meio de hashing perceptual.<sup>[[1]](#references)</sup>
- No teste de 920 páginas, 361 glifos únicos foram correspondidos (100%), com um SSIM médio de 0,9527.<sup>[[1]](#references)</sup>
- O relatório de origem descreve o EPUB reconstruído como praticamente indistinguível do original.<sup>[[1]](#references)</sup>

## References

- [1] [Como reverti a ofuscação da Web do Kindle da Amazon porque o aplicativo deles era ruim (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – renderizador de SVG para PNG](https://cairosvg.org/)
- [3] [imagehash – hashing perceptual de imagens (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Índice de Similaridade Estrutural (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – propriedades de preenchimento](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – biblioteca de renderização de SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
