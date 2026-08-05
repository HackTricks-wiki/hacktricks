# Esteganografia de Imagens

{{#include ../../banners/hacktricks-training.md}}

A maioria dos image stego em CTFs se enquadra em uma destas categorias:

- LSB/bit-planes (PNG/BMP)
- Payloads em metadados/comentários
- Anomalias em chunks PNG / reparo de corrupção
- Ferramentas no domínio DCT de JPEG (OutGuess etc.)
- Baseado em frames (GIF/APNG)

## Triagem rápida

Priorize evidências no nível do container antes de uma análise aprofundada do conteúdo:

- Valide o arquivo e inspecione a estrutura: `file`, `magick identify -verbose`, validadores de formato (por exemplo, `pngcheck`).
- Extraia metadados e strings visíveis: `exiftool -a -u -g1`, `strings`.
- Verifique se há conteúdo incorporado/anexado: `binwalk` e inspeção do final do arquivo (`tail | xxd`).
- Escolha de acordo com o container:
- PNG/BMP: bit-planes/LSB e anomalias no nível dos chunks.
- JPEG: metadados + ferramentas no domínio DCT (famílias no estilo OutGuess/F5).
- GIF/APNG: extração de frames, diferenciação entre frames, técnicas com paleta.

## Bit-planes / LSB

### Technique

PNG/BMP são populares em CTFs porque armazenam pixels de uma forma que facilita a **manipulação em nível de bits**. O mecanismo clássico de ocultação/extração é:

- Cada canal de pixel (R/G/B/A) possui vários bits.
- O **least significant bit** (LSB) de cada canal altera muito pouco a imagem.
- Invasores ocultam dados nesses bits de baixa ordem, às vezes usando um stride, uma permutação ou uma escolha por canal.

O que esperar nos desafios:

- O payload está em apenas um canal (por exemplo, `R` LSB).
- O payload está no canal alpha.
- O payload é comprimido/codificado após a extração.
- A mensagem está espalhada entre planes ou oculta por meio de XOR entre planes.

Famílias adicionais que você pode encontrar (dependendo da implementação):

- **LSB matching** (não apenas invertendo o bit, mas fazendo ajustes de +/-1 para corresponder ao bit desejado)
- **Ocultação baseada em palette/index** (PNG/GIF indexados: o payload está nos índices de cores, e não no RGB bruto)
- **Payload somente no alpha** (completamente invisível na visualização RGB)

### Tooling

#### zsteg

`zsteg` enumera vários padrões de extração de LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: executa uma bateria de transforms (metadata, image transforms, brute forcing de variantes de LSB).
- `stegsolve`: filtros visuais manuais (isolamento de canais, inspeção de planes, XOR etc.).

Download do Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Tricks de visibilidade baseados em FFT

FFT não é extração de LSB; ela é usada em casos onde o conteúdo está deliberadamente oculto no domínio da frequência ou em padrões sutis.

- Demo da EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage baseada na Web frequentemente usada em CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internals de PNG: chunks, corrupção e dados ocultos

### Técnica

PNG é um formato baseado em chunks. Em muitos challenges, o payload é armazenado no nível do container/chunk, e não nos valores dos pixels:

- **Bytes extras após `IEND`** (muitos viewers ignoram bytes finais)
- **Chunks ancillary não padronizados** carregando payloads
- **Headers corrompidos** que ocultam dimensões ou fazem parsers falharem até serem corrigidos

Locais de chunks com alta probabilidade que devem ser revisados:

- `tEXt` / `iTXt` / `zTXt` (metadata de texto, às vezes comprimida)
- `iCCP` (perfil ICC) e outros chunks ancillary usados como carrier
- `eXIf` (dados EXIF em PNG)

### Comandos de triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
O que procurar:

- Combinações estranhas de largura/altura/profundidade de bits/tipo de cor
- Erros de CRC/chunk (`pngcheck` geralmente indica o offset exato)
- Avisos sobre dados adicionais após `IEND`

Se precisar de uma visão mais detalhada dos chunks:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referências úteis:

- Especificação PNG (estrutura, chunks): https://www.w3.org/TR/PNG/
- Truques de formatos de arquivo (casos extremos de PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadados, ferramentas no domínio DCT e limitações do ELA

### Técnica

JPEG não é armazenado como pixels brutos; ele é comprimido no domínio DCT. É por isso que as ferramentas de stego para JPEG diferem das ferramentas LSB para PNG:

- Payloads de metadados/comentários ficam no nível do arquivo (alto sinal e rápidos de inspecionar)
- Ferramentas de stego no domínio DCT incorporam bits em coeficientes de frequência

Operacionalmente, trate JPEG como:

- Um container para segmentos de metadados (alto sinal, rápido de inspecionar)
- Um domínio de sinal comprimido (coeficientes DCT) no qual operam ferramentas de stego especializadas

### Verificações rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Locais com maior probabilidade:

- Metadados EXIF/XMP/IPTC
- Segmento de comentário JPEG (`COM`)
- Segmentos de aplicação (`APP1` para EXIF, `APPn` para dados do fornecedor)

### Ferramentas comuns

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se você estiver enfrentando payloads do steghide em JPEGs, considere usar `stegseek` (bruteforce mais rápido que scripts antigos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA destaca diferentes artefatos de recompressão; pode indicar regiões que foram editadas, mas não é um detector de stego por si só:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imagens animadas

### Técnica

Para imagens animadas, presuma que a mensagem esteja:

- Em um único frame (fácil), ou
- Espalhada pelos frames (a ordenação é importante), ou
- Visível apenas ao comparar frames consecutivos

### Extrair frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Depois, trate os frames como PNGs normais: `zsteg`, `pngcheck`, isolamento de canais.

Ferramentas alternativas:

- `gifsicle --explode anim.gif` (extração rápida de frames)
- `imagemagick`/`magick` para transformações por frame

A diferenciação entre frames costuma ser decisiva:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Codificação de contagem de pixels em APNG

- Detecte contêineres APNG: `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraia os quadros sem alterar a temporização: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupere payloads codificados como contagens de pixels por quadro:
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
Desafios animados podem codificar cada byte como a contagem de uma cor específica em cada frame; concatenar as contagens reconstrói a mensagem.<sup>[[1]](#references)</sup>

## Embedding protegido por senha

Se você suspeitar de um embedding protegido por uma passphrase, em vez de manipulação no nível dos pixels, este geralmente é o caminho mais rápido.

### steghide

Suporta `JPEG, BMP, WAV, AU` e pode embedar/extrair payloads criptografados.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Suporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Referências

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
