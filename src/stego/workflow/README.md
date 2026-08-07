# Fluxo de trabalho de Stego

{{#include ../../banners/hacktricks-training.md}}

A maioria dos problemas de stego é resolvida mais rapidamente por meio de uma triagem sistemática do que tentando ferramentas aleatórias.

## Fluxo principal

### Checklist de triagem rápida

O objetivo é responder a duas perguntas com eficiência:

1. Qual é o container/formato real?
2. O payload está nos metadados, em bytes anexados, em arquivos incorporados ou em stego no nível do conteúdo?

#### 1) Identifique o container
```bash
file target
ls -lah target
```
Se `file` e a extensão discordarem, confie no `file`. Trate formatos comuns como contêineres quando apropriado (por exemplo, documentos OOXML são arquivos ZIP).

#### 2) Procure metadados e strings óbvias
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
Se a extração falhar, mas forem relatadas assinaturas, extraia manualmente os offsets com `dd` e execute `file` novamente na região extraída.

#### 4) Se for uma imagem

- Inspecione anomalias: `magick identify -verbose file`
- Se for PNG/BMP, enumere bit-planes/LSB: `zsteg -a file.png`
- Valide a estrutura PNG: `pngcheck -v file.png`
- Use filtros visuais (Stegsolve / StegoVeritas) quando o conteúdo puder ser revelado por transformações de canal/plane

#### 5) Se for áudio

- Comece pelo espectrograma (Sonic Visualiser)
- Decodifique/inspecione os streams: `ffmpeg -v info -i file -f null -`
- Se o áudio se parecer com tons estruturados, teste a decodificação DTMF

### Ferramentas essenciais

Estas detectam os casos mais comuns no nível do container: payloads de metadados, bytes anexados e arquivos incorporados disfarçados pela extensão.<sup>[[1]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Repositório: https://github.com/korczis/foremost

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
### Contêineres, dados anexados e truques poliglotas

Muitos desafios de esteganografia são bytes extras após um arquivo válido ou arquivos compactados incorporados disfarçados pela extensão.

#### Cargas anexadas

Muitos formatos ignoram bytes finais. Um ZIP/PDF/script pode ser anexado a um contêiner de imagem/áudio.

Verificações rápidas:
```bash
binwalk file
tail -c 200 file | xxd
```
Se você souber de um offset, faça carving com `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Quando o `file` estiver confuso, procure por magic bytes com `xxd` e compare com assinaturas conhecidas:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Tente `7z` e `unzip` mesmo que a extensão não indique que é um zip:
```bash
7z l file
unzip -l file
```
### Anomalias próximas a stego

Links rápidos para padrões que aparecem regularmente adjacentes a stego (QR a partir de binário, braille etc.).

#### QR codes a partir de binário

Se o comprimento de um blob for um quadrado perfeito, ele pode conter pixels brutos de uma imagem/QR.
```python
import math
math.isqrt(2500)  # 50
```
Auxiliar de binário para imagem:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Referências

- [1] [DominicBreuker/stego-toolkit - Docker image com as ferramentas de esteganografia mais populares reunidas](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
