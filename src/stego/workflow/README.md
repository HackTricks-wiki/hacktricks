# Fluxo de Stego

{{#include ../../banners/hacktricks-training.md}}

A maioria dos problemas de stego é resolvida mais rapidamente com uma triagem sistemática do que com a tentativa de ferramentas aleatórias.

## Fluxo principal

### Lista de verificação de triagem rápida

O objetivo é responder a duas perguntas com eficiência:

1. Qual é o verdadeiro container/formato?
2. O payload está em metadados, bytes anexados, arquivos incorporados ou stego no nível do conteúdo?

#### 1) Identifique o container

```bash
file target
ls -lah target
```

Se `file` e a extensão não corresponderem, investigue a assinatura em vez de confiar no sufixo. `file` também é heurístico e pode ser confundido por entradas malformadas ou poliglotas. Trate formatos comuns como contêineres quando apropriado (por exemplo, documentos OOXML são pacotes ZIP).<sup>[[2]](#references)</sup>

#### 2) Procure metadados e strings óbvias

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Experimente várias codificações:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Verifique se há dados anexados / arquivos incorporados

```bash
binwalk target
binwalk -e target
```

Se a extração falhar, mas forem reportadas assinaturas, extraia manualmente os offsets com `dd` e execute `file` novamente na região extraída.

#### 4) Se for uma imagem

- Inspecione anomalias: `magick identify -verbose file`
- Se for PNG/BMP, enumere bit-planes/LSB: `zsteg -a file.png`
- Valide a estrutura PNG: `pngcheck -v file.png`
- Use filtros visuais (Stegsolve / StegoVeritas) quando o conteúdo puder ser revelado por transformações de canal/plano

#### 5) Se for áudio

- Comece pelo espectrograma (Sonic Visualiser)
- Decodifique/inspecione os streams: `ffmpeg -v info -i file -f null -`
- Se o áudio se parecer com tons estruturados, teste a decodificação DTMF

### Ferramentas essenciais

Elas identificam casos comuns no nível do contêiner: payloads em metadados, bytes anexados e arquivos incorporados disfarçados pela extensão.<sup>[[1]](#references)[[3]](#references)</sup>

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

Repositório do projeto: `korczis/foremost`.<sup>[[4]](#references)</sup>

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

### Contêineres, dados anexados e técnicas de polyglot

Muitos desafios de esteganografia envolvem bytes extras após um arquivo válido ou arquivos compactados incorporados e disfarçados pela extensão.

#### Payloads anexados

Muitos formatos ignoram bytes no final. Um ZIP/PDF/script pode ser anexado a um contêiner de imagem/áudio.

Verificações rápidas:

```bash
binwalk file
tail -c 200 file | xxd
```

Se você souber um offset, faça carving com `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Bytes mágicos

Quando `file` ficar confuso, procure bytes mágicos com `xxd` e compare-os com assinaturas conhecidas:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Tente `7z` e `unzip` mesmo que a extensão não indique que é um arquivo zip:

```bash
7z l file
unzip -l file
```

### Estranhezas relacionadas a stego

Links rápidos para padrões que aparecem regularmente junto a stego (QR a partir de binário, braille etc.).

#### Códigos QR a partir de binário

Se o comprimento de um blob for um quadrado perfeito, ele pode conter pixels brutos de uma imagem/QR.

```python
import math
math.isqrt(2500)  # 50
```

Auxiliar de conversão de binário para imagem:

- Auxiliar de imagem binária do dCode.<sup>[[5]](#references)</sup>

#### Braille

- Tradutor de Braille da Branah.<sup>[[6]](#references)</sup>

Para coleções mais amplas de utilitários de esteganografia e recursos específicos de técnicas, consulte o stego-toolkit incluído e a lista selecionada por 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Imagem Docker com as ferramentas de esteganografia mais populares reunidas](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Convenções de empacotamento aberto ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Imagem binária](https://www.dcode.fr/binary-image)
- [6] [Branah — Tradutor de Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Recursos de esteganografia](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
