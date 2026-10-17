# Trucos de PNG

{{#include ../../../banners/hacktricks-training.md}}

Los **archivos PNG** son muy comunes en **CTFs**, **respuesta a incidentes** y **preparación de malware**, porque son **lossless**, están **basados en chunks** y muchas herramientas los muestran sin problema, incluso cuando contienen **metadatos adicionales**, **payloads añadidos** o **chunks parcialmente dañados**.

Trata un PNG como un **contenedor**, no solo como una imagen.

## Análisis inicial

Empieza con comprobaciones a nivel de contenedor antes de pasar al stego LSB. Para el flujo de trabajo con bit planes/LSB, consulta [la página específica sobre stego en imágenes](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Elementos útiles que conviene buscar:

- **Chunks auxiliares inesperados** como `tEXt`, `zTXt`, `iTXt`, `eXIf` o `iCCP`
- **Errores de CRC** o longitudes de chunk malformadas
- **Datos adicionales después de `IEND`**
- **Varios marcadores `IEND`** o fragmentos `IDAT` recuperables después del final formal del archivo
- Un archivo que sea un PNG válido **y** que también parezca un ZIP/PDF/script al extraer sus datos

Recuerda que la estructura mínima válida suele ser:

- `IHDR` (debe ir primero)
- `IDAT` (uno o más chunks consecutivos)
- `IEND` (debe ir al final)

## Datos posteriores a `IEND`

Uno de los artefactos PNG con mayor valor de señal es **la información añadida después del chunk `IEND` final**. Muchos decodificadores la ignoran, por lo que resulta útil para:

- **Esteganografía sencilla / payloads ocultos**
- **PNG polyglots**
- **Preparación de malware**
- **Recuperar datos de imágenes antiguas** de editores con errores

Detección rápida:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Una búsqueda de bytes de `IEND` es solo una pista: los mismos bytes pueden aparecer en los datos de un chunk o en un trailer falsificado. Para extraerlo de forma fiable, recorre los chunks prefijados por longitud desde la firma PNG y detente en el primer `IEND` estructural; el [recorredor de chunks de abajo](#extract-ancillary-chunk-payloads) también guarda el trailer.<sup>[[6]](#references)</sup>

Prueba también analizadores genéricos de archivos directamente con el PNG o con el trailer extraído:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Recuperación al estilo Acropalypse de capturas de pantalla recortadas o censuradas

Un truco forense muy práctico para PNG consiste en comprobar si un editor de capturas de pantalla **sobrescribió** un PNG sin **truncar** primero el archivo antiguo. En esos casos, pueden quedar bytes de la **imagen anterior** después de `IEND` y, a veces, se pueden reconstruir parcialmente datos adicionales de `IDAT`.

Esto se hizo muy conocido con **aCropalypse** (Google Pixel Markup) y el problema relacionado de **Windows Snipping Tool**.<sup>[[3]](#references)</sup> En la práctica, si un PNG «recortado» o «censurado» aún contiene datos antiguos al final del archivo, quizá puedas recuperar parte de la captura de pantalla original.<sup>[[1]](#references)</sup>

Flujo de trabajo práctico:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Señales que justifican claramente un análisis más profundo:

- `pngcheck` informa de **datos adicionales después de `IEND`**
- Encuentras **más de un `IEND`**
- Encuentras **chunks `IDAT` adicionales** después del final aparente de la imagen
- La captura de pantalla procede de un dispositivo/editor que se sabe que se vio afectado

Si esto ocurre, procesa el archivo con una herramienta de recuperación de **aCropalypse** antes de considerar fiable la censura.

## Abuso de chunks relevante en la práctica

Los chunks PNG más interesantes para las investigaciones no suelen ser los de imagen más obvios, sino los que pueden contener **texto**, **metadatos** o **bytes de payload**:

- `tEXt` / `zTXt` / `iTXt`: metadatos de texto y texto comprimido
- `eXIf`: datos EXIF dentro de PNG
- `iCCP`: perfil ICC incrustado
- `PLTE`: datos de paleta en imágenes indexadas, pero también útil en escenarios de payload-smuggling.<sup>[[2]](#references)</sup>

Vuelca su contenido con:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Para la persistencia de payloads ofensivos dentro de chunks PNG (por ejemplo, trucos con **PLTE**, **IDAT** o **tEXt** que sobreviven a algunas transformaciones de imágenes PHP), consulta aquí las notas más detalladas centradas en la carga de archivos:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Extraer payloads de chunks auxiliares

Un atacante puede colocar bytes arbitrarios en un **chunk auxiliar desconocido antes de `IEND`**. Los decodificadores PNG normales pueden ignorar un chunk auxiliar desconocido, mientras que un script que obtiene la imagen como bytes puede leer y usar el payload; abrir el PNG por sí solo no lo ejecuta.<sup>[[4]](#references)[[6]](#references)</sup> La investigación original mostró un chunk personalizado comprimido y cifrado.<sup>[[4]](#references)</sup> Un ejemplo posterior en un navegador usó los bytes extraídos para proporcionar HTML o una descarga.<sup>[[5]](#references)</sup>

Una primera letra minúscula en el tipo de chunk significa *auxiliar*; una segunda letra minúscula significa *privado*. Por ejemplo, `paMP` es privado, mientras que `pAMP` usa el espacio de nombres público, aunque este último se inventó para la demostración.<sup>[[4]](#references)[[6]](#references)</sup> Un chunk tiene la estructura `longitud (4 bytes, big-endian) | tipo (4 bytes) | datos | CRC (4 bytes)`; el CRC cubre el tipo y los datos. Analiza esta estructura en lugar de buscar con grep un nombre de tipo dentro de los datos comprimidos de `IDAT`. El siguiente recorrido valida los límites y los CRC, exporta los payloads de chunks auxiliares como bytes sin procesar y escribe los bytes posteriores al `IEND` estructural en `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Extraer chunks auxiliares y el tráiler PNG</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Inspecciona los bytes extraídos con `file`, `strings` o `binwalk`; descomprime solo si el carrier está realmente comprimido.<sup>[[4]](#references)</sup> Volver a codificar puede eliminar el carrier, así que compara los bytes cargados con los recuperados antes de confiar en él.<sup>[[2]](#references)[[6]](#references)</sup>

## Reparación de PNG corruptos

Para comprobar la integridad y localizar el área exacta dañada, **pngcheck** sigue siendo una de las mejores herramientas iniciales:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Si el archivo está dañado y no es malicioso intencionalmente, **PCRT** puede ser útil en CTF y en el trabajo de laboratorio para corregir problemas comunes, como encabezados incorrectos, valores IHDR equivocados, problemas de CRC o diseños de chunks malformados.

Si tu objetivo es **sanitizar** un PNG que contiene datos sospechosos al final del archivo, preservando la imagen visible, ExifTool puede eliminar explícitamente esos datos:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Para pruebas sensibles, trabaja siempre sobre una **copia** y guarda los hashes del original antes de intentar repararlo.



## References

- [1] [Explotación de aCropalypse: recuperación de PNG truncados](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payloads de PHP persistentes en PNG: cómo inyectar código PHP en una imagen y mantenerlo allí](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Los chunks auxiliares son el lugar perfecto para guardar información confidencial](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Uso de chunks auxiliares válidos para introducir datos de contrabando en un endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Especificación Portable Network Graphics (PNG) (tercera edición)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
