# Esteganografia em imagens

{{#include ../../banners/hacktricks-training.md}}

A maioria dos desafios de esteganografia em imagens de CTF se enquadra em uma destas categorias:

- LSB/planos de bits (PNG/BMP)
- Payloads em metadados/comentários
- Anomalias em chunks PNG / reparo de corrupção
- Ferramentas de domínio DCT para JPEG (OutGuess etc.)
- Baseados em frames (GIF/APNG)

## Triagem rápida

Priorize as evidências no nível do contêiner antes de analisar o conteúdo em profundidade:

- Valide o arquivo e inspecione a estrutura: `file`, `magick identify -verbose`, validadores de formato (por exemplo, `pngcheck`).
- Extraia metadados e strings visíveis: `exiftool -a -u -g1`, `strings`.
- Verifique se há conteúdo incorporado/anexado: `binwalk` e inspeção do fim do arquivo (`tail | xxd`).
- Escolha a abordagem conforme o contêiner:
  - PNG/BMP: planos de bits/LSB e anomalias no nível dos chunks.
  - JPEG: metadados + ferramentas de domínio DCT (famílias no estilo OutGuess/F5).
  - GIF/APNG: extração de frames, comparação entre frames e truques com paletas.

## Planos de bits / LSB

### Técnica

PNG/BMP são populares em CTFs porque armazenam pixels de uma forma que facilita a **manipulação em nível de bits**. O mecanismo clássico para ocultar/extrair dados é:

- Cada canal de pixel (R/G/B/A) tem vários bits.
- O **bit menos significativo** (LSB) de cada canal altera muito pouco a imagem.
- Atacantes ocultam dados nesses bits de ordem inferior, às vezes usando um stride, uma permutação ou uma seleção por canal.

O que esperar nos desafios:

- O payload está em apenas um canal (por exemplo, no LSB de `R`).
- O payload está no canal alfa.
- O payload é comprimido/codificado após a extração.
- A mensagem é distribuída entre planos ou ocultada usando XOR entre planos.

Outras famílias que você pode encontrar (dependendo da implementação):

- **LSB matching** (não apenas inverter o bit, mas fazer ajustes de +/-1 para corresponder ao bit desejado)
- **Ocultação baseada em paleta/índice** (PNG/GIF indexados: payload nos índices de cor, em vez de nos valores RGB brutos)
- **Payloads somente no canal alfa** (completamente invisíveis na visualização RGB)

### Ferramentas

#### zsteg

`zsteg` enumera muitos padrões de extração de LSB/planos de bits para PNG/BMP:

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

- Demo da EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Ferramentas web de triagem frequentemente usadas em CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internos do PNG: chunks, corrupção e dados ocultos

### Técnica

PNG é um formato baseado em chunks. Em muitos desafios, o payload é armazenado no nível do contêiner/chunk, e não nos valores dos pixels:

- **Bytes extras após `IEND`** (muitos visualizadores ignoram os bytes finais)
- **Chunks auxiliares não padronizados** que transportam payloads; consulte o [fluxo de trabalho de análise de chunks PNG e extração de dados](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Cabeçalhos corrompidos** que ocultam dimensões ou fazem os parsers falharem até serem corrigidos

Locais de chunks importantes a verificar:

- `tEXt` / `iTXt` / `zTXt` (metadados de texto, às vezes comprimidos)
- `iCCP` (perfil ICC) e outros chunks auxiliares usados como meio de transporte
- `eXIf` (dados EXIF em PNG)

### Comandos de triagem

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

O que procurar:

- Combinações incomuns de largura/altura/profundidade de bits/tipo de cor
- Erros de CRC/chunk (o pngcheck geralmente indica o deslocamento exato)
- Avisos sobre dados adicionais após `IEND`

Se precisar de uma visualização mais detalhada dos chunks:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Referências úteis:

- Especificação PNG (estrutura, chunks): https://www.w3.org/TR/PNG/
- Truques de formatos de arquivo (casos extremos de PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadados, ferramentas no domínio DCT e limitações do ELA

### Técnica

JPEG não é armazenado como pixels brutos; é comprimido no domínio DCT. Por isso, as ferramentas de stego para JPEG diferem das ferramentas LSB para PNG:

- Payloads de metadados/comentários ficam no nível do arquivo (alto sinal e rápidos de inspecionar)
- Ferramentas de stego no domínio DCT incorporam bits em coeficientes de frequência

Na prática, trate JPEG como:

- Um contêiner para segmentos de metadados (alto sinal, rápido de inspecionar)
- Um domínio de sinal comprimido (coeficientes DCT) no qual ferramentas especializadas de stego operam

### Verificações rápidas

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Locais com maior probabilidade de conter sinais:

- Metadados EXIF/XMP/IPTC
- Segmento de comentário JPEG (`COM`)
- Segmentos de aplicação (`APP1` para EXIF, `APPn` para dados do fornecedor)

### Ferramentas comuns

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se estiver lidando especificamente com payloads do steghide em JPEGs, considere usar `stegseek` (bruteforce mais rápido que scripts antigos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Análise de nível de erro

ELA destaca diferentes artefatos de recompressão; pode indicar regiões que foram editadas, mas não é, por si só, um detector de esteganografia:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imagens animadas

### Técnica

Para imagens animadas, considere que a mensagem está:

- Em um único quadro (fácil), ou
- Distribuída por vários quadros (a ordem importa), ou
- Visível apenas ao fazer diff entre quadros consecutivos

### Extrair quadros

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Depois, trate os quadros como PNGs normais: `zsteg`, `pngcheck`, isolamento de canais.

Ferramentas alternativas:

- `gifsicle --explode anim.gif` (extração rápida de quadros)
- `imagemagick`/`magick` para transformações quadro a quadro

A comparação das diferenças entre quadros costuma ser decisiva:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Codificação por contagem de pixels em APNG

- Detecte contêineres APNG: `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraia os quadros sem alterar o tempo: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupere os payloads codificados como contagens de pixels por quadro:

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

Se você suspeitar que a incorporação é protegida por uma senha em vez de envolver manipulação em nível de pixel, este costuma ser o caminho mais rápido.

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

Repositório: https://github.com/Paradoxis/StegCracker

### stegpy

Compatível com PNG/BMP/GIF/WebP/WAV.

Repositório: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — pink, Lista de Desejos do Santa, Metadados de Natal, Ruído Capturado](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
