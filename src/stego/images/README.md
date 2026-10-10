# Esteganografia de imagens

{{#include ../../banners/hacktricks-training.md}}

A maioria dos casos de esteganografia em imagens de CTF se enquadra em uma destas categorias:

- LSB/planos de bits (PNG/BMP)
- Payloads em metadados/comentários
- Anomalias/correção de corrupção em chunks PNG
- Ferramentas de domínio DCT de JPEG (OutGuess etc.)
- Baseada em quadros (GIF/APNG)

## Triagem rápida

Priorize evidências no nível do contêiner antes de uma análise profunda do conteúdo:

- Valide o arquivo e inspecione a estrutura: `file`, `magick identify -verbose`, validadores de formato (por exemplo, `pngcheck`).
- Extraia metadados e strings visíveis: `exiftool -a -u -g1`, `strings`.
- Verifique se há conteúdo incorporado/anexado: `binwalk` e inspeção do fim do arquivo (`tail | xxd`).
- Escolha a abordagem conforme o contêiner:
  - PNG/BMP: planos de bits/LSB e anomalias no nível dos chunks.
  - JPEG: metadados e ferramentas de domínio DCT (famílias no estilo OutGuess/F5).
  - GIF/APNG: extração de quadros, comparação entre quadros e truques com paletas.

## Planos de bits / LSB

### Técnica

PNG/BMP são populares em CTFs porque armazenam pixels de uma forma que facilita a **manipulação em nível de bits**. O mecanismo clássico de ocultação/extração é:

- Cada canal de pixel (R/G/B/A) tem vários bits.
- O **bit menos significativo** (LSB) de cada canal altera muito pouco a imagem.
- Atacantes ocultam dados nesses bits de ordem inferior, às vezes usando um passo, uma permutação ou uma seleção de canal.

O que esperar nos desafios:

- O payload está em apenas um canal (por exemplo, no LSB de `R`).
- O payload está no canal alfa.
- O payload é comprimido/codificado após a extração.
- A mensagem está distribuída entre planos ou oculta por meio de XOR entre planos.

Outras famílias que você pode encontrar (dependendo da implementação):

- **LSB matching** (não apenas alternar o bit, mas fazer ajustes de +/-1 para corresponder ao bit desejado)
- **Ocultação baseada em paleta/índice** (PNG/GIF indexados: payload nos índices de cor, em vez dos valores RGB brutos)
- **Payloads apenas no canal alfa** (completamente invisíveis na visualização RGB)

### Ferramentas

#### zsteg

`zsteg` enumera muitos padrões de extração de LSB/planos de bits para PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: executa uma série de transformações (metadados, transformações de imagem, força bruta de variantes LSB).
- `stegsolve`: filtros visuais manuais (isolamento de canais, inspeção de planos, XOR etc.).

Download do Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Truques de visibilidade baseados em FFT

FFT não é extração de LSB; ela é útil nos casos em que o conteúdo é ocultado deliberadamente no espaço de frequências ou em padrões sutis.

- Demonstração da EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

A triagem baseada na Web é frequentemente usada em CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internos do PNG: chunks, corrupção e dados ocultos

### Técnica

PNG é um formato baseado em chunks. Em muitos desafios, o payload é armazenado no nível do contêiner/chunk, em vez de nos valores dos pixels:

- **Bytes extras após `IEND`** (muitos visualizadores ignoram os bytes finais)
- **Chunks ancillary não padronizados** que carregam payloads
- **Cabeçalhos corrompidos** que ocultam dimensões ou impedem o funcionamento dos parsers até serem corrigidos

Locais de chunks com alta probabilidade de conter dados:

- `tEXt` / `iTXt` / `zTXt` (metadados de texto, às vezes comprimidos)
- `iCCP` (perfil ICC) e outros chunks ancillary usados como portadores
- `eXIf` (dados EXIF em PNG)

### Comandos de triagem

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

O que procurar:

- Combinações incomuns de largura/altura/profundidade de bits/tipo de cor
- Erros de CRC/chunk (pngcheck geralmente indica o offset exato)
- Avisos sobre dados adicionais após `IEND`

Se precisar de uma visualização mais detalhada dos chunks:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Referências úteis:

- Especificação PNG (estrutura, chunks): https://www.w3.org/TR/PNG/
- Truques de formato de arquivo (casos especiais de PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, ferramentas de domínio DCT e limitações do ELA

### Técnica

JPEG não é armazenado como pixels brutos; é comprimido no domínio DCT. Por isso, as ferramentas de stego para JPEG são diferentes das ferramentas de LSB para PNG:

- Payloads de metadata/comentários ficam no nível do arquivo (alto sinal e rápidos de inspecionar)
- Ferramentas de stego no domínio DCT incorporam bits em coeficientes de frequência

Operacionalmente, trate JPEG como:

- Um contêiner para segmentos de metadata (alto sinal, rápidos de inspecionar)
- Um domínio de sinal comprimido (coeficientes DCT) no qual operam ferramentas de stego especializadas

### Verificações rápidas

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Locais com alto sinal:

- Metadados EXIF/XMP/IPTC
- Segmento de comentário JPEG (`COM`)
- Segmentos de aplicação (`APP1` para EXIF, `APPn` para dados do fornecedor)

### Ferramentas comuns

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se estiver lidando especificamente com payloads steghide em JPEGs, considere usar `stegseek` (bruteforce mais rápido que scripts mais antigos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA destaca diferentes artefatos de recompressão; pode indicar regiões que foram editadas, mas não é um detector de stego por si só:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imagens animadas

### Técnica

Para imagens animadas, considere que a mensagem está:

- Em um único frame (fácil), ou
- Distribuída entre frames (a ordem importa), ou
- Visível apenas quando você compara frames consecutivos

### Extrair frames

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Em seguida, trate os quadros como PNGs normais: `zsteg`, `pngcheck`, isolamento de canais.

Ferramentas alternativas:

- `gifsicle --explode anim.gif` (extração rápida de quadros)
- `imagemagick`/`magick` para transformações por quadro

A comparação entre quadros costuma ser decisiva:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Codificação por contagem de pixels em APNG

- Detecte contêineres APNG: `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraia os frames sem alterar a temporização: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupere payloads codificados como contagens de pixels por frame:

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

Desafios animados podem codificar cada byte como a contagem de uma cor específica em cada quadro; concatenar as contagens reconstrói a mensagem.<sup>[[1]](#references)</sup>

## Incorporação protegida por senha

Se você suspeita que a incorporação está protegida por uma frase-senha, em vez de envolver manipulação em nível de pixel, esse costuma ser o caminho mais rápido.

### steghide

Compatível com `JPEG, BMP, WAV, AU` e capaz de incorporar/extrair payloads criptografados.

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

## References

- [1] [Flagvent 2025 (Médio) — rosa, Lista de Desejos do Papai Noel, Metadados de Natal, Ruído Capturado](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
