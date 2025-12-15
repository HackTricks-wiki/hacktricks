# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

A maioria do image stego em CTFs se reduz a uma destas categorias:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triagem rápida

Priorize evidências a nível de container antes da análise profunda do conteúdo:

- Valide o arquivo e inspecione a estrutura: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extraia metadados e strings visíveis: `exiftool -a -u -g1`, `strings`.
- Verifique conteúdo embutido/anexado: `binwalk` e inspeção do fim-do-arquivo (`tail | xxd`).
- Prossiga por tipo de container:
- PNG/BMP: bit-planes/LSB e anomalias a nível de chunk.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: extração de frames, diferenciação de frames, truques com paleta.

## Bit-planes / LSB

### Técnica

PNG/BMP são populares em CTFs porque armazenam pixels de forma que facilita a **manipulação a nível de bit**. O mecanismo clássico de esconder/extração é:

- Cada canal de pixel (R/G/B/A) tem múltiplos bits.
- O **bit menos significativo** (LSB) de cada canal altera a imagem muito pouco.
- Atacantes escondem dados nesses bits de baixa ordem, às vezes com um stride, permutação ou escolha por canal.

O que esperar em desafios:

- O payload está em apenas um canal (e.g., `R` LSB).
- O payload está no canal alpha.
- O payload é comprimido/codificado após extração.
- A mensagem é espalhada entre planos ou escondida via XOR entre planos.

Famílias adicionais que você pode encontrar (dependente da implementação):

- **LSB matching** (não apenas inverter o bit, mas ajustes +/-1 para coincidir com o bit alvo)
- **Palette/index-based hiding** (indexed PNG/GIF: payload em índices de cor em vez de raw RGB)
- **Alpha-only payloads** (completamente invisível na visualização RGB)

### Ferramentas

#### zsteg

`zsteg` enumera muitos padrões de extração LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: executa uma bateria de transformações (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: filtros visuais manuais (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is not LSB extraction; it is for cases where content is deliberately hidden in frequency space or subtle patterns.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Técnica

PNG é um formato baseado em chunks. Em muitos desafios o payload é armazenado no nível do container/chunk em vez de nos valores de pixel:

- **Bytes extras após `IEND`** (muitos visualizadores ignoram bytes finais)
- **Non-standard ancillary chunks** carregando payloads
- **Cabeçalhos corrompidos** que escondem dimensões ou quebram parsers até serem corrigidos

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (metadados de texto, às vezes comprimidos)
- `iCCP` (ICC profile) e outros ancillary chunks usados como carrier
- `eXIf` (dados EXIF em PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
O que procurar:

- Estranhas combinações de width/height/bit-depth/colour-type
- Erros de CRC/chunk (pngcheck normalmente aponta para o offset exato)
- Avisos sobre dados adicionais após `IEND`

Se precisar de uma visão mais detalhada dos chunks:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referências úteis:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadados, ferramentas no domínio DCT, e limitações do ELA

### Técnica

JPEG não é armazenado como pixels brutos; é comprimido no domínio DCT. Por isso as ferramentas stego para JPEG diferem das ferramentas LSB para PNG:

- Metadados/payloads de comentário são de nível de arquivo (alto sinal e fáceis de inspecionar)
- Ferramentas stego no domínio DCT embutem bits em coeficientes de frequência

Operacionalmente, trate o JPEG como:

- Um container para segmentos de metadados (alto sinal, fáceis de inspecionar)
- Um domínio de sinal comprimido (coeficientes DCT) onde ferramentas stego especializadas operam

### Verificações rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Locais de alto sinal:

- Metadados EXIF/XMP/IPTC
- Segmento de comentário JPEG (`COM`)
- Segmentos de aplicação (`APP1` para EXIF, `APPn` para dados do fornecedor)

### Ferramentas comuns

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se você está lidando especificamente com payloads do steghide em JPEGs, considere usar `stegseek` (bruteforce mais rápido que scripts mais antigos):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA destaca diferentes artefatos de recompressão; pode indicar regiões que foram editadas, mas não é um detector de stego por si só:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Imagens animadas

### Técnica

Para imagens animadas, assuma que a mensagem está:

- Em um único quadro (fácil), ou
- Distribuída por vários quadros (a ordem importa), ou
- Apenas visível quando você compara (diff) quadros consecutivos

### Extrair quadros
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Depois trate os frames como PNGs normais: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (extração rápida de frames)
- `imagemagick`/`magick` para transformações por frame

Frame differencing é frequentemente decisivo:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Incorporação protegida por senha

Se suspeitar que a incorporação está protegida por uma senha em vez de manipulação ao nível dos pixels, este normalmente é o caminho mais rápido.

### steghide

Suporta `JPEG, BMP, WAV, AU` e pode incorporar/extrair payloads criptografados.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repositório: https://github.com/Paradoxis/StegCracker

### stegpy

Suporta PNG/BMP/GIF/WebP/WAV.

Repositório: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
