# Esteganografia de Imagens

{{#include ../../banners/hacktricks-training.md}}

A maioria dos desafios de stego de imagem em CTF se resume a um destes grupos:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triagem rápida

Priorize evidências ao nível do contêiner antes da análise profunda do conteúdo:

- Valide o arquivo e inspecione a estrutura: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extraia metadata e strings visíveis: `exiftool -a -u -g1`, `strings`.
- Verifique conteúdo embutido/anexado: `binwalk` e inspeção de fim-de-arquivo (`tail | xxd`).
- Siga por tipo de contêiner:
- PNG/BMP: bit-planes/LSB e anomalias em nível de chunk.
- JPEG: metadata + ferramentas no domínio DCT (famílias OutGuess/F5-style).
- GIF/APNG: extração de frames, diferença entre frames, truques de paleta.

## Bit-planes / LSB

### Técnica

PNG/BMP são populares em CTFs porque armazenam pixels de forma que torna a manipulação a nível de bit fácil. O mecanismo clássico de esconder/extrair é:

- Cada canal de pixel (R/G/B/A) possui múltiplos bits.
- O **least significant bit** (LSB) de cada canal altera muito pouco a imagem.
- Atacantes escondem dados nesses bits de baixa ordem, às vezes com um stride, permutação ou escolha por canal.

O que esperar em desafios:

- O payload está em apenas um canal (por exemplo, `R` LSB).
- O payload está no canal alpha.
- Payload é comprimido/encodado após extração.
- A mensagem está espalhada por planos ou escondida via XOR entre planos.

Outras famílias que você pode encontrar (dependendo da implementação):

- **LSB matching** (não apenas invertendo o bit, mas ajustes de +/-1 para corresponder ao bit alvo)
- **Palette/index-based hiding** (indexed PNG/GIF: payload em índices de cor em vez de RGB bruto)
- **Alpha-only payloads** (payload apenas no alpha, completamente invisível na visualização RGB)

### Ferramentas

#### zsteg

`zsteg` enumera muitos padrões de extração LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: runs a battery of transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: manual visual filters (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is not LSB extraction; it is for cases where content is deliberately hidden in frequency space or subtle patterns.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG é um formato em chunks. Em muitos desafios o payload é armazenado ao nível do container/chunk em vez de nos valores de pixel:

- **Extra bytes after `IEND`** (muitos viewers ignoram bytes finais)
- **Non-standard ancillary chunks** carregando payloads
- **Corrupted headers** que ocultam dimensões ou quebram parsers até serem corrigidos

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (metadados de texto, às vezes comprimidos)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
O que procurar:

- Combinações estranhas de width/height/bit-depth/colour-type
- Erros de CRC/chunk (pngcheck geralmente aponta para o offset exato)
- Avisos sobre dados adicionais após `IEND`

Se precisar de uma visualização de chunk mais aprofundada:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referências úteis:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadados, ferramentas em domínio DCT e limitações da ELA

### Técnica

JPEG não é armazenado como pixels brutos; é comprimido no domínio DCT. É por isso que as ferramentas stego para JPEG diferem das ferramentas PNG LSB:

- Metadados/comentários (payloads) são de nível de arquivo (alto sinal e rápidos de inspecionar)
- Ferramentas stego em domínio DCT inserem bits em coeficientes de frequência

Operacionalmente, trate o JPEG como:

- Um contêiner para segmentos de metadados (alto sinal, rápidos de inspecionar)
- Um domínio de sinal comprimido (coeficientes DCT) onde ferramentas stego especializadas operam

### Verificações rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Locais de alto sinal:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Ferramentas comuns

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se você estiver lidando especificamente com steghide payloads em JPEGs, considere usar `stegseek` (bruteforce mais rápido que scripts mais antigos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA destaca diferentes artefatos de recompressão; pode apontar regiões que foram editadas, mas não é um detector de stego por si só:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imagens animadas

### Técnica

Para imagens animadas, assuma que a mensagem está:

- Em um único frame (fácil), ou
- Distribuída por frames (a ordem importa), ou
- Visível apenas quando você diff frames consecutivos

### Extrair frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Então trate os frames como PNGs normais: `zsteg`, `pngcheck`, channel isolation.

Ferramentas alternativas:

- `gifsicle --explode anim.gif` (extração rápida de frames)
- `imagemagick`/`magick` para transformações por frame

Frame differencing is often decisive:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Detectar contêineres APNG: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Extrair frames sem re-temporização: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recuperar payloads codificados como contagens de pixels por frame:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Desafios animados podem codificar cada byte como a contagem de uma cor específica em cada quadro; concatenar as contagens reconstrói a mensagem.

## Incorporação protegida por senha

Se você suspeitar que a incorporação está protegida por uma passphrase em vez de manipulação ao nível de pixels, este é normalmente o caminho mais rápido.

### steghide

Suporta `JPEG, BMP, WAV, AU` e pode embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Não tenho acesso direto ao repositório. Cole aqui o conteúdo de src/stego/images/README.md (ou a seção "StegCracker" que quer traduzida) que devo traduzir para português, que eu faço a tradução mantendo a mesma sintaxe markdown/html.
```bash
stegcracker file.jpg wordlist.txt
```
Repositório: https://github.com/Paradoxis/StegCracker

### stegpy

Suporta PNG/BMP/GIF/WebP/WAV.

Repositório: https://github.com/dhsdshdhk/stegpy

## Referências

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
