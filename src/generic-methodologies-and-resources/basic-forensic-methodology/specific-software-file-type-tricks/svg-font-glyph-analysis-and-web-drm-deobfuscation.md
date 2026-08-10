# Análise de Glyphs de SVG/Fontes e Deobfuscation de Web DRM (Raster Hashing + SSIM)

Esta página documenta técnicas práticas para recuperar texto de leitores web que enviam sequências de glyphs posicionadas junto com definições de glyphs vetoriais por requisição (caminhos SVG) e que randomizam os IDs dos glyphs a cada requisição para impedir scraping. A ideia central é ignorar os IDs numéricos de glyphs específicos da requisição e identificar as formas visuais por meio de raster hashing, mapeando então as formas para caracteres com SSIM em comparação com um atlas de fonte de referência. A mesma abordagem pode ser generalizada para visualizadores com proteções semelhantes.<sup>[[1]](#references)</sup>

Aviso: Use estas técnicas somente para fazer backup de conteúdo que você possui legitimamente e em conformidade com as leis e os termos aplicáveis.

## Aquisição (exemplo: Kindle Cloud Reader)

Endpoint observado:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiais necessários por sessão:<sup>[[1]](#references)</sup>
- Cookies da sessão do navegador (login normal da Amazon)
- Token de renderização obtido de uma chamada à API startReading
- Token de sessão ADP adicional usado pelo renderer

Comportamento:<sup>[[1]](#references)</sup>
- Cada requisição, quando enviada com headers e cookies equivalentes aos do navegador, retorna um arquivo TAR limitado a 5 páginas.
- Para um livro longo, serão necessários muitos lotes; cada lote usa um mapeamento randomizado diferente dos IDs dos glyphs.

Conteúdo típico do TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — sequências de texto posicionadas como sequências de IDs de glyphs (não Unicode)
- glyphs.json — definições de caminhos SVG por requisição para cada glyph e fontFamily
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
- Os paths podem incluir pequenos movimentos relativos (por exemplo, `m3,1 m1,6 m-4,-7`) que confundem muitos parsers de vetores e a amostragem ingênua de paths.
- Sempre renderize paths preenchidos completos com um mecanismo SVG robusto (por exemplo, CairoSVG), em vez de fazer diferenciação de comandos/coordenadas.

## Por que a decodificação ingênua falha

- Substituição de glifos randomizada por requisição: o mapeamento de ID do glifo→caractere muda a cada lote; os IDs não têm significado global.<sup>[[1]](#references)</sup>
- A comparação direta de coordenadas SVG é frágil: formas idênticas podem diferir nas coordenadas numéricas ou na codificação dos comandos a cada requisição.<sup>[[1]](#references)</sup>
- O OCR em glifos isolados tem desempenho ruim (≈50%), confunde pontuação e glifos visualmente semelhantes e ignora ligaduras.<sup>[[1]](#references)</sup>

## Pipeline funcional: normalização e mapeamento de glifos independente de requisições

1) Rasterizar os glifos SVG por requisição
- Construa um documento SVG mínimo por glifo com o `path` fornecido e renderize-o em uma tela de tamanho fixo (por exemplo, 512×512) usando CairoSVG ou um mecanismo equivalente que lide com sequências de paths complexas.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderize preenchido em preto sobre branco; evite strokes para eliminar artefatos dependentes do renderer e do AA.

2) Perceptual hashing para identidade entre requisições
- Calcule um perceptual hash (por exemplo, pHash via `imagehash.phash`) de cada imagem de glifo.<sup>[[3]](#references)</sup>
- Trate o hash como um ID estável: a mesma forma visual em diferentes requisições é reduzida ao mesmo perceptual hash, neutralizando IDs randomizados.

3) Geração de um atlas de fontes de referência
- Baixe as fontes TTF/OTF-alvo (por exemplo, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Renderize candidatos para A–Z, a–z, 0–9, pontuação, marcas especiais (travessões em/em, aspas) e ligaduras explícitas: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantenha atlas separados para cada variante da fonte (normal/italic/bold/bold-italic).
- Use um text shaper adequado (HarfBuzz) se quiser fidelidade em nível de glifo para ligaduras; a rasterização simples via Pillow ImageFont pode ser suficiente se você renderizar diretamente as strings de ligaduras e o mecanismo de shaping resolvê-las.

4) Correspondência de similaridade visual com SSIM
- Para cada imagem de glifo desconhecida, calcule SSIM (Structural Similarity Index) em relação a todas as imagens candidatas em todos os atlas de variantes de fonte.<sup>[[4]](#references)</sup>
- Atribua a string de caracteres da melhor correspondência. O SSIM absorve melhor pequenas diferenças de antialiasing, escala e coordenadas do que comparações pixel a pixel.<sup>[[1]](#references)[[4]](#references)</sup>

5) Tratamento de bordas e reconstrução
- Quando um glifo corresponder a uma ligadura (com vários caracteres), expanda-a durante a decodificação.<sup>[[1]](#references)</sup>
- Use retângulos de execução (top/left/right/bottom) para inferir quebras de parágrafo (diferenças em Y), alinhamento (padrões em X), estilo e tamanhos.<sup>[[1]](#references)</sup>
- Serialize para HTML/EPUB preservando `fontStyle`, `fontWeight`, `fontSize` e links internos.<sup>[[1]](#references)</sup>

### Dicas de implementação

- Normalize todas as imagens para o mesmo tamanho e escala de cinza antes de calcular o hash e o SSIM.
- Armazene em cache por perceptual hash para evitar recalcular o SSIM para glifos repetidos entre lotes.
- Use um tamanho de rasterização de alta qualidade (por exemplo, 256–512 px) para melhorar a distinção; reduza a escala conforme necessário antes do SSIM para acelerá-lo.
- Se usar Pillow para renderizar candidatos TTF, defina o mesmo tamanho de tela e centralize o glifo; adicione padding para evitar cortar ascendentes/descendentes.

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

O relatório de origem usou a geometria dos runs, campos de estilo e metadados de links para preservar a formatação do documento reconstruído.<sup>[[1]](#references)</sup>

- Quebras de parágrafo: Se o topo Y do próximo run exceder a baseline da linha anterior por um limite (relativo ao tamanho da fonte), iniciar um novo parágrafo.<sup>[[1]](#references)</sup>
- Alinhamento: Agrupar por X esquerdo semelhante para parágrafos alinhados à esquerda; detectar linhas centralizadas por margens simétricas; detectar alinhamento à direita pelas bordas direitas.
- Estilo: Preservar itálico/negrito via `fontStyle`/`fontWeight`; variar classes CSS por faixas de `fontSize` para aproximar títulos e corpo do texto.
- Links: Se os runs incluírem metadados de links (por exemplo, `positionId`), emitir âncoras e hrefs internos.

## Mitigando truques de anti-scraping com paths SVG

- Usar paths preenchidos com `fill-rule: nonzero` e um renderer apropriado (CairoSVG, resvg). Não depender da normalização dos tokens do path.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Evitar rendering de strokes; concentrar-se em sólidos preenchidos para contornar artefatos de linhas finas causados por micro movimentos relativos.
- Manter um viewBox estável por renderização para que formas idênticas sejam rasterizadas de modo consistente entre batches.

## Observações de performance

- Na prática, os livros convergem para algumas centenas de glyphs únicos (por exemplo, ~361 incluindo ligaturas). Armazenar os resultados de SSIM em cache por hash perceptual.<sup>[[1]](#references)</sup>
- Após a descoberta inicial, os batches futuros reutilizam predominantemente hashes conhecidos; a decodificação torna-se limitada por I/O.
- O relatório citado observou um SSIM médio de aproximadamente 0,95; sinalizar correspondências com pontuação baixa para revisão manual.<sup>[[1]](#references)</sup>

## Generalização para outros viewers

O workflow do Kindle sugere que viewers semelhantes podem aceitar a mesma normalização quando eles:<sup>[[1]](#references)</sup>
- retornam glyph runs posicionados com IDs numéricos específicos da requisição
- enviam glyphs vetoriais por requisição (paths SVG ou subset fonts)
- limitam o número de páginas por requisição

…podem ser tratados com a mesma normalização:
- Rasterizar formas por requisição → hash perceptual → ID da forma
- Atlas de glyphs/ligaturas candidatos por variante de fonte
- SSIM (ou métrica perceptual semelhante) para atribuir caracteres
- Reconstruir o layout a partir de retângulos/estilos dos runs

## Exemplo mínimo de aquisição (rascunho)

Usar as DevTools do navegador para capturar os headers, cookies e tokens exatos usados pelo leitor ao solicitar `/renderer/render`. Em seguida, reproduzi-los a partir de um script ou curl.<sup>[[1]](#references)</sup> Esboço do exemplo:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Ajuste a parametrização (ASIN do livro, janela de páginas, viewport) para corresponder às solicitações do leitor. Considere um limite de 5 páginas por solicitação.<sup>[[1]](#references)</sup>

## Resultados alcançáveis

- Reduza mais de 100 alfabetos randomizados a um único espaço de glifos usando hashing perceptual.<sup>[[1]](#references)</sup>
- No teste citado de 920 páginas, 361 glifos exclusivos foram correspondidos (100%), com um SSIM médio de 0.9527.<sup>[[1]](#references)</sup>
- O relatório de origem descreve o EPUB reconstruído como praticamente indistinguível do original.<sup>[[1]](#references)</sup>

## References

- [1] [Como reverti a ofuscação web do Kindle da Amazon porque o aplicativo deles era ruim (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – renderizador de SVG para PNG](https://cairosvg.org/)
- [3] [imagehash – hashing perceptual de imagens (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Índice de Similaridade Estrutural (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – propriedades de preenchimento](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – biblioteca de renderização de SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
