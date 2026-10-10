# Flujo de trabajo de Stego

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los problemas de stego se resuelven más rápido mediante un triaje sistemático que probando herramientas al azar.

## Flujo básico

### Lista de verificación para un triaje rápido

El objetivo es responder eficientemente a dos preguntas:

1. ¿Cuál es el contenedor/formato real?
2. ¿Está el payload en los metadatos, en bytes añadidos, en archivos incrustados o en stego a nivel de contenido?

#### 1) Identificar el contenedor

```bash
file target
ls -lah target
```

Si `file` y la extensión no coinciden, investiga la firma en lugar de confiar en el sufijo. `file` también es heurístico y puede confundirse con entradas malformadas o poliglotas. Trata los formatos comunes como contenedores cuando corresponda (por ejemplo, los documentos OOXML son paquetes ZIP).<sup>[[2]](#references)</sup>

#### 2) Busca metadatos y cadenas evidentes

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Prueba varias codificaciones:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Buscar datos anexados / archivos incrustados

```bash
binwalk target
binwalk -e target
```

Si la extracción falla pero se reportan firmas, extrae manualmente los offsets con `dd` y vuelve a ejecutar `file` en la región extraída.

#### 4) Si es una imagen

- Inspecciona anomalías: `magick identify -verbose file`
- Si es PNG/BMP, enumera bit-planes/LSB: `zsteg -a file.png`
- Valida la estructura PNG: `pngcheck -v file.png`
- Usa filtros visuales (Stegsolve / StegoVeritas) cuando el contenido pueda revelarse mediante transformaciones de canal/plano

#### 5) Si es audio

- Primero, analiza el espectrograma (Sonic Visualiser)
- Decodifica/inspecciona los streams: `ffmpeg -v info -i file -f null -`
- Si el audio se parece a tonos estructurados, prueba la decodificación DTMF

### Herramientas de uso habitual

Estas detectan casos frecuentes a nivel de contenedor: payloads en metadatos, bytes añadidos y archivos incrustados disfrazados por la extensión.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk

```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```

Repositorio: https://github.com/ReFirmLabs/binwalk

#### Foremost

```bash
foremost -i file
```

Repositorio del proyecto: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### file / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Contenedores, datos añadidos y trucos de polyglot

Muchos retos de esteganografía consisten en bytes adicionales después de un archivo válido o en archivos comprimidos incrustados y disfrazados con otra extensión.

#### Cargas útiles añadidas

Muchos formatos ignoran los bytes finales. Se puede añadir un ZIP/PDF/script a un contenedor de imagen/audio.

Comprobaciones rápidas:

```bash
binwalk file
tail -c 200 file | xxd
```

Si conoces un desplazamiento, extrae con `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

Cuando `file` se confunda, busca magic bytes con `xxd` y compáralos con firmas conocidas:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Prueba `7z` y `unzip` aunque la extensión no indique que sea un archivo zip:

```bash
7z l file
unzip -l file
```

### Rarezas cercanas al stego

Enlaces rápidos a patrones que suelen aparecer junto al stego (QR a partir de binario, braille, etc.).

#### Códigos QR a partir de binario

Si la longitud de un blob es un cuadrado perfecto, puede tratarse de píxeles sin procesar de una imagen/QR.

```python
import math
math.isqrt(2500)  # 50
```

Ayudante de binario a imagen:

- Ayudante de imagen binaria de dCode.<sup>[[5]](#references)</sup>

#### Braille

- Traductor de Braille de Branah.<sup>[[6]](#references)</sup>

Para ver colecciones más amplias de utilidades de esteganografía y recursos específicos de técnicas, consulta el stego-toolkit incluido y la lista seleccionada por 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Imagen Docker con las herramientas de esteganografía más populares reunidas](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Convenciones de empaquetado abierto ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Imagen binaria](https://www.dcode.fr/binary-image)
- [6] [Branah — Traductor de Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Recursos de esteganografía](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
