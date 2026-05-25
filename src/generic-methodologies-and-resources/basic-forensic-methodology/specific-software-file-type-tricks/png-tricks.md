# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Los archivos PNG** son muy comunes en **CTFs**, **incident response** y **malware staging** porque son **sin pérdida**, **basados en chunks**, y muchas herramientas los renderizarán sin problemas incluso cuando contienen **metadatos extra**, **payloads añadidos** o **chunks parcialmente corruptos**.

Trata un PNG como un **contenedor**, no solo como una imagen.

## Triage rápido

Empieza con comprobaciones a nivel de contenedor antes de pasar a LSB stego. Para el flujo de trabajo de bit-plane/LSB, consulta [la página dedicada a image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Cosas útiles para buscar:

- **Unexpected ancillary chunks** como `tEXt`, `zTXt`, `iTXt`, `eXIf` o `iCCP`
- **CRC errors** o longitudes de chunk malformadas
- **Additional data after `IEND`**
- **Multiple `IEND` markers** o fragmentos `IDAT` recuperables después del final formal del archivo
- Un archivo que sea un PNG válido **y** además parezca un ZIP/PDF/script cuando se carvea

Recuerda que la estructura mínima válida suele ser:

- `IHDR` (debe ir primero)
- `IDAT` (uno o más chunks consecutivos)
- `IEND` (debe ir al final)

## Trailing data after `IEND`

Uno de los artefactos PNG con mayor valor de señal es **data appended after the final `IEND` chunk**. Muchos decoders lo ignoran, lo que lo hace útil para:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** de editores defectuosos

Detección rápida:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Si quieres extraer todo lo que va después del `IEND` final:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Además, prueba parsers genéricos de archivos directamente contra el PNG o el trailer extraído:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recuperación estilo Acropalypse de capturas recortadas/redactadas

Un truco forense PNG muy práctico y reciente es comprobar si un editor de capturas **sobrescribió** un PNG sin **truncar** primero el archivo antiguo. En esos casos, bytes de la **imagen anterior** pueden quedar después de `IEND`, y a veces datos extra de `IDAT` pueden reconstruirse parcialmente.

Esto se hizo muy conocido con **aCropalypse** (Google Pixel Markup) y el problema relacionado de **Windows Snipping Tool**. En la práctica, si un PNG "recortado" o "redactado" aún contiene datos antiguos al final, puede que puedas recuperar parte de la captura original.

Flujo de trabajo práctico:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Señales que justifican fuertemente un análisis más profundo:

- `pngcheck` informa **datos adicionales después de `IEND`**
- Encuentras **más de un `IEND`**
- Encuentras **chunks `IDAT` extra** después del aparente final de la imagen
- La captura de pantalla provino de un dispositivo/editor conocido por haber sido afectado

Si esto ocurre, pasa el archivo a una **aCropalypse recovery tool** antes de tratar la redacción como confiable.

## Chunk abuse que importa en la práctica

Los chunks PNG más interesantes para investigaciones suelen no ser los obvios de imagen, sino los chunks que pueden llevar **texto**, **metadata** o **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata de texto y texto comprimido
- `eXIf` – datos EXIF dentro de PNG
- `iCCP` – perfil ICC incrustado
- `PLTE` – datos de paleta en imágenes indexadas, pero también útil en escenarios de payload-smuggling

Extráelos con:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Para persistencia de payload ofensivo dentro de chunks PNG (por ejemplo **PLTE**, **IDAT**, o trucos **tEXt** que sobreviven a algunas transformaciones de imágenes PHP), consulta las notas más detalladas centradas en uploads aquí:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Reparación de PNG corrupto

Para comprobar la integridad y localizar la zona exacta dañada, **pngcheck** sigue siendo una de las mejores primeras herramientas:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Si el archivo está dañado en lugar de ser intencionalmente malicioso, **PCRT** puede ser útil en CTFs y trabajo de laboratorio para corregir problemas comunes como headers malos, valores IHDR incorrectos, problemas de CRC o layouts de chunks malformados.

Si tu objetivo es **sanitizar** un PNG que contiene datos de trailer sospechosos mientras preservas la imagen visible, ExifTool puede eliminar explícitamente el trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Para evidencia sensible, trabaja siempre sobre una **copia** y conserva hashes del original antes de intentar reparaciones.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
