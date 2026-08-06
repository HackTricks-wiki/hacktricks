# Trucos de PNG

{{#include ../../../banners/hacktricks-training.md}}

**Los archivos PNG** son muy comunes en **CTFs**, **respuesta a incidentes** y **malware staging** porque son **sin pérdida**, **basados en chunks** y muchas herramientas los renderizan sin problemas incluso cuando contienen **metadatos adicionales**, **payloads añadidos** o **chunks parcialmente corruptos**.

Trata un PNG como un **contenedor**, no solo como una imagen.

## Triage rápido

Comienza con comprobaciones a nivel de contenedor antes de pasar a LSB stego. Para el flujo de trabajo de bit-plane/LSB, consulta [la página específica sobre image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Cosas útiles que buscar:

- **Chunks auxiliares inesperados** como `tEXt`, `zTXt`, `iTXt`, `eXIf` o `iCCP`
- **Errores CRC** o longitudes de chunk malformadas
- **Datos adicionales después de `IEND`**
- **Múltiples marcadores `IEND`** o fragmentos `IDAT` recuperables después del final formal del archivo
- Un archivo que sea un PNG válido **y** que también parezca un ZIP/PDF/script al hacer carving

Recuerda que la estructura válida mínima normalmente es:

- `IHDR` (debe ser el primero)
- `IDAT` (uno o más chunks consecutivos)
- `IEND` (debe ser el último)

## Datos posteriores a `IEND`

Uno de los artefactos PNG con mayor valor como indicador es la **información añadida después del chunk `IEND` final**. Muchos decoders la ignoran, lo que hace que sea útil para:

- **Simple stego / payloads ocultos**
- **PNG polyglots**
- **Malware staging**
- **Recuperar datos de imágenes anteriores** de editores con errores

Detección rápida:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Si quieres extraer todo lo que aparece después del `IEND` final:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Prueba también analizadores genéricos de archivos comprimidos directamente contra el PNG o el tráiler extraído:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recuperación al estilo Acropalypse de capturas de pantalla recortadas/censuradas

Un truco forense de PNG muy práctico y reciente consiste en comprobar si un editor de capturas de pantalla **sobrescribió** un PNG sin **truncar** primero el archivo antiguo. En esos casos, pueden quedar bytes de la **imagen anterior** después de `IEND`, y a veces se pueden reconstruir parcialmente datos `IDAT` adicionales.

Esto se hizo conocido con **aCropalypse** (Google Pixel Markup) y el problema relacionado de **Windows Snipping Tool**. En la práctica, si un PNG "recortado" o "censurado" todavía contiene datos antiguos al final, es posible que puedas recuperar parte de la captura de pantalla original.<sup>[[1]](#references)</sup>

Flujo de trabajo práctico:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Señales que justifican firmemente un análisis más profundo:

- `pngcheck` informa de **datos adicionales después de `IEND`**
- Encuentras **más de un `IEND`**
- Encuentras **chunks `IDAT` adicionales** después del final aparente de la imagen
- La captura de pantalla procede de un dispositivo/editor que se sabe que ha sido afectado

Si ocurre esto, pasa el archivo por una **aCropalypse recovery tool** antes de considerar fiable la redacción.

## Abuso de chunks relevante en la práctica

Los chunks PNG más interesantes para las investigaciones no suelen ser los elementos de imagen obvios, sino los chunks que pueden transportar **texto**, **metadatos** o **bytes de payload**:

- `tEXt` / `zTXt` / `iTXt` – metadatos de texto y texto comprimido
- `eXIf` – datos EXIF dentro de PNG
- `iCCP` – perfil ICC incrustado
- `PLTE` – datos de paleta en imágenes indexadas, pero también útiles en escenarios de payload-smuggling<sup>[[2]](#references)</sup>

Extráelos con:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Para la persistencia de payloads ofensivos dentro de chunks PNG (por ejemplo, trucos con **PLTE**, **IDAT** o **tEXt** que sobreviven a algunas transformaciones de imágenes en PHP), consulta las notas más detalladas centradas en uploads aquí<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Reparación de PNG corruptos

Para comprobar la integridad y localizar el área exacta dañada, **pngcheck** sigue siendo una de las mejores primeras herramientas:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Si el archivo está dañado en lugar de ser malicioso intencionadamente, **PCRT** puede ser útil en CTFs y trabajos de laboratorio para corregir problemas comunes, como headers incorrectos, valores IHDR erróneos, problemas de CRC o diseños de chunks con formato incorrecto.

Si tu objetivo es **sanitizar** un PNG que contiene datos sospechosos al final, conservando la imagen visible, ExifTool puede eliminar explícitamente dichos datos:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Para evidencia sensible, trabaja siempre sobre una **copia** y conserva los hashes del original antes de intentar repararlo.

## Referencias

- [1] [Explotando aCropalypse: Recuperación de PNGs truncados](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payloads PHP persistentes en PNGs: Cómo inyectar código PHP en una imagen y mantenerlo allí](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
