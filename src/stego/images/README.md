# Esteganografia em imagens

{{#include ../../banners/hacktricks-training.md}}

A esteganografia em imagens de CTF geralmente se enquadra em uma destas categorias:

- LSB/planos de bits (PNG/BMP)
- Payloads em metadados/comentários
- Estranhezas nos chunks PNG / reparo de corrupção
- Ferramentas no domínio DCT de JPEG (OutGuess etc.)
- Baseada em quadros (GIF/APNG)

## Triagem rápida

Priorize evidências no nível do contêiner antes de uma análise profunda do conteúdo. Consulte o [fluxo de trabalho geral de esteganografia](../workflow/) para identificação e extração de arquivos antes dos testes específicos para imagens.

- Valide o arquivo e inspecione a estrutura: `file`, `magick identify -verbose`, validadores de formato (por exemplo, `pngcheck`).
- Extraia metadados e strings visíveis: `exiftool -a -u -g1`, `strings`.
- Verifique se há conteúdo embutido/anexado: `binwalk` e inspeção do fim do arquivo (`tail | xxd`).
- Escolha a abordagem conforme o contêiner:
  - PNG/BMP: planos de bits/LSB e anomalias no nível dos chunks.
  - JPEG: metadados + ferramentas no domínio DCT (famílias no estilo OutGuess/F5).
  - GIF/APNG: extração de quadros, comparação entre quadros, truques com paletas.

## Planos de bits / LSB

### Técnica

PNG/BMP são populares em CTFs porque armazenam pixels de uma forma que facilita a **manipulação em nível de bits**. O mecanismo clássico de ocultação/extração é:

- Cada canal do pixel (R/G/B/A) tem vários bits.
- O **bit menos significativo** (LSB) de cada canal altera muito pouco a imagem.
- Atacantes ocultam dados nesses bits de ordem inferior, às vezes usando um passo, uma permutação ou uma escolha de canal por canal.

O que esperar em desafios:

- O payload está em apenas um canal (por exemplo, o LSB de `R`).
- O payload está no canal alfa.
- O payload é compactado/codificado após a extração.
- A mensagem está distribuída entre planos ou oculta por meio de XOR entre planos.

Outras famílias que você pode encontrar (dependendo da implementação):

- **Correspondência de LSB** (não apenas inverter o bit, mas fazer ajustes de +/-1 para corresponder ao bit desejado)
- **Ocultação baseada em paleta/índice** (PNG/GIF indexado: payload nos índices de cor em vez de RGB bruto)
- **Payloads somente no canal alfa** (completamente invisíveis na visualização RGB)

### Índices de paleta de cores indexadas

Um PNG ou GIF indexado armazena um **índice** da paleta por pixel, não uma tupla RGB. Dois índices podem corresponder à mesma cor visível; portanto, converter para RGB antes da análise pode apagar a distinção oculta. Inspecione as entradas duplicadas ou quase duplicadas da paleta e, em seguida, renderize uma máscara binária dos pixels que usam cada índice suspeito. Isso revelou texto oculto e alterações em QR codes em desafios recentes de GIF.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Para um PNG indexado de quadro único (ou o **primeiro quadro** de um GIF), mantenha o modo `P` do Pillow e altere `target` para um índice interessante indicado pelo script. Verifique a transparência (`tRNS` ou o índice de transparência do GIF), além do RGB, ao escolher os índices.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Para GIFs animados, inspecione os quadros separadamente. O Pillow normalmente converte os quadros posteriores para RGB/RGBA durante a composição; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` mantém o modo `P` somente enquanto a paleta não muda. Se um quadro tiver uma paleta local ou já tiver sido composto, inspecione os dados originais do quadro indexado em vez de tratar os pixels convertidos para RGB como índices.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Ferramentas

#### zsteg

`zsteg` enumera muitos padrões de extração LSB/planos de bits para PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: executa uma série de transformações (metadados, transformações de imagem, força bruta em variantes de LSB).
- `stegsolve`: filtros visuais manuais (isolamento de canais, inspeção de planos, XOR etc.).

Download do Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Truques de visibilidade baseados em FFT

FFT não é extração de LSB; ela é usada quando o conteúdo é ocultado deliberadamente no espaço de frequências ou em padrões sutis.

- Demonstração da EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triagem baseada na Web frequentemente usada em CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Estrutura interna de PNG: chunks, corrupção e dados ocultos

### Técnica

PNG é um formato baseado em chunks. Em muitos desafios, o payload é armazenado no nível do contêiner/chunk, em vez de nos valores dos pixels:

- **Bytes extras após `IEND`** (muitos visualizadores ignoram os bytes finais)
- **Chunks auxiliares não padrão** que transportam payloads; consulte o [processo de análise de chunks PNG e extração de dados](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Cabeçalhos corrompidos** que ocultam as dimensões ou impedem o funcionamento dos parsers até serem corrigidos

Locais de chunks com alta probabilidade de conter dados que devem ser verificados:

- `tEXt` / `iTXt` / `zTXt` (metadados de texto, às vezes comprimidos)
- `iCCP` (perfil ICC) e outros chunks auxiliares usados como portadores
- `eXIf` (dados EXIF em PNG)

### Bytes de filtro das scanlines de PNG como portadores

PNG armazena um byte de tipo de filtro (0–4) antes de cada scanline no fluxo `IDAT` descomprimido. Esses bytes não são valores de pixel; os pixels RGB decodificados não preservam as escolhas de filtro originais, e uma nova codificação pode alterá-las. Um codificador pode variar os filtros legitimamente, mas padrões deliberados podem codificar uma mensagem pequena; um desafio recente usou valores de filtro de 1–4 como símbolos de dois bits. Inspecione o **arquivo original** e concatene todos os dados `IDAT` antes de descomprimir. Para o caso a seguir, de RGB/RGBA não entrelaçado de 8 bits, o stride é a largura multiplicada pelo número de canais; imagens Adam7 exigem larguras de scanline específicas para cada passagem.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Listar bytes de filtro das scanlines de PNG sem recodificar</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Execute com `python3 filters.py suspect.png`. Verifique se a sequência de filtros, e não os pixels decodificados, segue um mapeamento plausível de símbolos. A escolha do mapeamento depende do desafio; a variação, por si só, não é prova de esteganografia.<sup>[[3]](#references)[[7]](#references)</sup>

### Comandos de triagem

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

O que procurar:

- Combinações estranhas de largura/altura/profundidade de bits/tipo de cor
- Erros de CRC/chunk (o pngcheck geralmente aponta o offset exato)
- Avisos sobre dados adicionais após `IEND`

Se precisar de uma visualização mais detalhada dos chunks:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Referências úteis:

- Especificação PNG (estrutura, chunks): https://www.w3.org/TR/PNG/
- Truques de formatos de arquivo (casos especiais de PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadados, ferramentas no domínio DCT e limitações do ELA

### Técnica

JPEG não é armazenado como pixels brutos; ele é comprimido no domínio DCT. É por isso que as ferramentas de stego para JPEG diferem das ferramentas LSB para PNG:

- Payloads de metadados/comentários ficam no nível do arquivo (alto sinal e rápidos de inspecionar)
- Ferramentas de stego no domínio DCT incorporam bits em coeficientes de frequência

Na prática, trate JPEG como:

- Um contêiner para segmentos de metadados (alto sinal, rápidos de inspecionar)
- Um domínio de sinal comprimido (coeficientes DCT) no qual ferramentas especializadas de stego operam

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

Se estiver lidando especificamente com payloads do steghide em JPEGs, considere usar `stegseek` (bruteforce mais rápido que scripts antigos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Análise de nível de erro

ELA destaca diferentes artefatos de recompressão; pode indicar regiões que foram editadas, mas não é, por si só, um detector de stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imagens animadas

### Técnica

Para imagens animadas, considere que a mensagem está:

- Em um único quadro (fácil), ou
- Distribuída entre quadros (a ordem importa), ou
- Visível apenas ao comparar quadros consecutivos

### Extrair quadros

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Depois, trate os quadros como PNGs normais: `zsteg`, `pngcheck`, isolamento de canais.

Ferramentas alternativas:

- `gifsicle --explode anim.gif` (extração rápida de quadros)
- `imagemagick`/`magick` para transformações quadro a quadro

A diferença entre quadros costuma ser decisiva:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Codificação por contagem de pixels em APNG

- Detecte contêineres APNG: `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraia os frames sem alterar o timing: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupere os payloads codificados como contagens de pixels por frame:

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

Se você suspeita que a incorporação é protegida por uma frase secreta, em vez de envolver manipulação no nível dos pixels, esse costuma ser o caminho mais rápido.

### steghide

Oferece suporte a `JPEG, BMP, WAV, AU` e pode incorporar/extrair payloads criptografados.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repositório: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Suporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — pink, Lista de desejos do Papai Noel, Metadados de Natal, Ruído capturado](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [Write-up do HackVent 2024 — Cores distorcidas](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Especificação Portable Network Graphics (PNG), Terceira edição](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Lá no fundo, há algo na água](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Formatos de arquivo de imagem do Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Especificação GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Protocolo Afterimage — write-up de CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
