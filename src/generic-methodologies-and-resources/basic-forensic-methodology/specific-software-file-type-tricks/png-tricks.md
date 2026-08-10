# Trucos de PNG

Los **archivos PNG** son muy comunes en **CTFs**, **respuesta ante incidentes** y **malware staging** porque son **sin pérdida**, **basados en chunks**, y muchas herramientas los muestran correctamente incluso cuando contienen **metadatos adicionales**, **payloads añadidos** o **chunks parcialmente corruptos**.

Trata un PNG como un **contenedor**, no solo como una imagen.

## Triaje rápido

Comienza con comprobaciones a nivel de contenedor antes de pasar a LSB stego. Para el flujo de trabajo de bit-plane/LSB, consulta [la página específica de image stego](../../../stego/images/README.md).
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

Uno de los artefactos PNG con mayor valor como indicador es la **información añadida después del chunk `IEND` final**. Muchos decodificadores la ignoran, lo que la hace útil para:

- **Stego simple / payloads ocultos**
- **PNG polyglots**
- **Malware staging**
- **Recuperar datos de imagen antiguos** de editores con errores

Detección rápida:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Si quieres extraer todo después del `IEND` final:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
También prueba directamente analizadores genéricos de archivos comprimidos contra el PNG o el tráiler recuperado:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recuperación al estilo Acropalypse de capturas de pantalla recortadas/censuradas

Un truco forense muy práctico y reciente para PNG consiste en comprobar si un editor de capturas de pantalla **sobrescribió** un PNG sin **truncar** primero el archivo antiguo. En esos casos, los bytes de la **imagen anterior** pueden permanecer después de `IEND`, y a veces se pueden reconstruir parcialmente datos `IDAT` adicionales.

Esto se hizo conocido gracias a **aCropalypse** (Google Pixel Markup) y al problema relacionado de **Windows Snipping Tool**.<sup>[[3]](#references)</sup> En la práctica, si un PNG "recortado" o "censurado" todavía contiene datos antiguos al final, es posible que puedas recuperar parte de la captura de pantalla original.<sup>[[1]](#references)</sup>

Flujo de trabajo práctico:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Indicadores que justifican claramente un análisis más profundo:

- `pngcheck` informa de **datos adicionales después de `IEND`**
- Encuentras **más de un `IEND`**
- Encuentras **chunks `IDAT` adicionales** después del final aparente de la imagen
- La captura de pantalla procede de un dispositivo/editor que se sabe que se ha visto afectado

Si ocurre esto, pasa el archivo por una **herramienta de recuperación de aCropalypse** antes de considerar fiable la redacción.

## Abuso de chunks relevante en la práctica

Los chunks PNG más interesantes para las investigaciones normalmente no son los obvios de la imagen, sino los chunks que pueden contener **texto**, **metadatos** o **bytes de payload**:

- `tEXt` / `zTXt` / `iTXt` – metadatos de texto y texto comprimido
- `eXIf` – datos EXIF dentro de PNG
- `iCCP` – perfil ICC incrustado
- `PLTE` – datos de paleta en imágenes indexadas, pero también útil en escenarios de payload-smuggling.<sup>[[2]](#references)</sup>

Extráelos con:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Para la persistencia de payloads ofensivos dentro de chunks PNG (por ejemplo, trucos con **PLTE**, **IDAT** o **tEXt** que sobreviven a algunas transformaciones de imágenes en PHP), consulta las notas más detalladas centradas en uploads aquí:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Para comprobar la integridad y localizar el área exacta dañada, **pngcheck** sigue siendo una de las mejores primeras herramientas:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Si el archivo está dañado en lugar de ser intencionadamente malicioso, **PCRT** puede resultar útil en CTFs y trabajos de laboratorio para corregir problemas comunes, como headers incorrectos, valores IHDR erróneos, problemas de CRC o estructuras de chunks malformadas.

Si tu objetivo es **sanitizar** un PNG que contiene datos sospechosos al final, preservando la imagen visible, ExifTool puede eliminar explícitamente esos datos finales:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Para las evidencias sensibles, trabaja siempre sobre una **copia** y conserva los hashes del original antes de intentar reparaciones.

## References

- [1] [Explotando aCropalypse: Recuperación de PNG truncados](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payloads persistentes de PHP en PNGs: Cómo inyectar código PHP en una imagen y mantenerlo allí](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
