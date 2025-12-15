# Fluxo de trabalho Stego

{{#include ../../banners/hacktricks-training.md}}

A maioria dos problemas stego é resolvida mais rapidamente por meio de triagem sistemática do que tentando ferramentas aleatórias.

## Fluxo principal

### Lista de verificação rápida de triagem

O objetivo é responder duas perguntas de forma eficiente:

1. Qual é o container/formato real?
2. O payload está em metadados, bytes anexados, arquivos embutidos ou stego em nível de conteúdo?

#### 1) Identificar o container
```bash
file target
ls -lah target
```
Se `file` e a extensão discordarem, confie em `file`. Considere formatos comuns como contêineres quando apropriado (por exemplo, documentos OOXML são arquivos ZIP).

#### 2) Look for metadata and obvious strings
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Tente várias codificações:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Verificar dados anexados / arquivos incorporados
```bash
binwalk target
binwalk -e target
```
Se a extração falhar mas assinaturas forem reportadas, recorte manualmente os offsets com `dd` e execute `file` novamente na região recortada.

#### 4) Se for imagem

- Inspecione anomalias: `magick identify -verbose file`
- Se PNG/BMP, enumere planos de bits/LSB: `zsteg -a file.png`
- Valide a estrutura PNG: `pngcheck -v file.png`
- Use filtros visuais (Stegsolve / StegoVeritas) quando o conteúdo pode ser revelado por transformações de canal/plano

#### 5) Se for áudio

- Espectrograma primeiro (Sonic Visualiser)
- Decodifique/inspecione streams: `ffmpeg -v info -i file -f null -`
- Se o áudio se assemelhar a tons estruturados, teste decodificação DTMF

### Ferramentas essenciais

Estas cobrem os casos de alto-frequência ao nível de container: metadata payloads, appended bytes e embedded files disfarçados pela extensão.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Não tenho acesso direto ao arquivo remoto. Por favor cole aqui o conteúdo do arquivo src/stego/workflow/README.md (ou a seção "Foremost") que você quer que eu traduza para português.
```bash
foremost -i file
```
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### arquivo / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Contêineres, dados anexados e truques polyglot

Muitos desafios de esteganografia consistem em bytes extras após um arquivo válido, ou em arquivos embutidos disfarçados pela extensão.

#### Payloads anexados

Muitos formatos ignoram bytes finais. Um ZIP/PDF/script pode ser anexado a um contêiner de imagem/áudio.

Verificações rápidas:
```bash
binwalk file
tail -c 200 file | xxd
```
Se souber o offset, carve com `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Bytes mágicos

Quando `file` está confuso, procure por bytes mágicos com `xxd` e compare com assinaturas conhecidas:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Tente `7z` e `unzip` mesmo se a extensão não indicar zip:
```bash
7z l file
unzip -l file
```
### Peculiaridades próximas ao stego

Links rápidos para padrões que aparecem regularmente adjacentes ao stego (QR-from-binary, braille, etc).

#### QR codes a partir de binário

Se o tamanho de um blob for um quadrado perfeito, pode ser pixels brutos para uma imagem/QR.
```python
import math
math.isqrt(2500)  # 50
```
Auxiliar binário-para-imagem:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Listas de referência

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
