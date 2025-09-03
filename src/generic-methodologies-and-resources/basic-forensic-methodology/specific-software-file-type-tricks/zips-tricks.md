# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Herramientas de línea de comandos** para gestionar **archivos zip** son esenciales para diagnosticar, reparar y crackear zip files. Aquí hay algunas utilidades clave:

- **`unzip`**: Revela por qué un archivo zip puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato zip.
- **`zipinfo`**: Lista el contenido de un archivo zip sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar archivos zip corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para brute-force de contraseñas de zip, efectiva para contraseñas de hasta aproximadamente 7 caracteres.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles exhaustivos sobre la estructura y estándares de los archivos zip.

Es crucial notar que los archivos zip protegidos por contraseña **no cifran los nombres de archivos ni los tamaños de los archivos** en su interior, un fallo de seguridad que no comparten RAR o 7z, los cuales sí cifran esa información. Además, los archivos zip encriptados con el método antiguo ZipCrypto son vulnerables a un **plaintext attack** si existe una copia no cifrada de un archivo comprimido disponible. Este ataque aprovecha el contenido conocido para crackear la contraseña del zip, una vulnerabilidad detallada en [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y explicada más a fondo en [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Sin embargo, los archivos zip protegidos con **AES-256** son inmunes a este plaintext attack, lo que demuestra la importancia de elegir métodos de cifrado seguros para datos sensibles.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

El malware moderno para Android (droppers) usa metadata ZIP malformada para romper herramientas estáticas (jadx/apktool/unzip) mientras mantiene el APK instalable en el dispositivo. Los trucos más comunes son:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- Colisiones de nombres de archivo/directorio para ocultar artefactos reales (por ejemplo, un directorio llamado `classes.dex/` junto al verdadero `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Síntomas:
- `jadx-gui` falla con errores como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` pide una contraseña para archivos core del APK aunque un APK válido no puede tener `classes*.dex`, `resources.arsc` o `AndroidManifest.xml` cifrados:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detección con zipdetails:
```bash
zipdetails -v sample.apk | less
```
Mira el General Purpose Bit Flag de los encabezados locales y centrales. Un valor revelador es el bit 0 activado (Encryption) incluso para entradas core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Si un APK se instala y se ejecuta en el dispositivo pero las entradas principales aparecen "encrypted" para las herramientas, el GPBF fue manipulado.

Solución: borrar el bit 0 del GPBF tanto en los Local File Headers (LFH) como en las entradas del Central Directory (CD). Minimal byte-patcher:
```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
out = bytearray(buf)
i = 0
patched = 0
while True:
i = out.find(sig, i)
if i == -1:
break
flags, = struct.unpack_from('<H', out, i + flag_off)
if flags & 1:  # encryption bit set
struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
patched += 1
i += 4  # move past signature to continue search
return bytes(out), patched

if __name__ == '__main__':
inp, outp = sys.argv[1], sys.argv[2]
data = open(inp, 'rb').read()
data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
open(outp, 'wb').write(data)
print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```
Uso:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Ahora deberías ver `General Purpose Flag  0000` en las entradas principales y las herramientas volverán a analizar el APK.

### 2) Extra fields grandes/personalizados para romper parsers

Los atacantes colocan Extra fields sobredimensionados e IDs extraños en los encabezados para provocar fallos en los decompilers. En entornos reales puede que veas marcadores personalizados (p. ej., cadenas como `JADXBLOCK`) incrustados allí.

Inspección:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Ejemplos observados: IDs desconocidos como `0xCAFE` ("Ejecutable Java") o `0x414A` ("JA:") que contienen grandes cargas útiles.

Heurísticas DFIR:
- Generar alerta cuando los campos Extra sean inusualmente grandes en entradas principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar los IDs Extra desconocidos en esas entradas como sospechosos.

Mitigación práctica: reconstruir el archivo (p. ej., re-zipping de los archivos extraídos) elimina los campos Extra maliciosos. Si las herramientas se niegan a extraer debido a un cifrado falso, primero borre el bit 0 de GPBF como se indicó arriba, y luego reempaque:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisiones de nombres de archivo/directorio (ocultando artefactos reales)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractors y decompilers se confunden y pueden sobreponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres core de APK como `classes.dex`.

Triage y extracción segura:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Detección programática post-fix:
```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
names = z.namelist()

collisions = defaultdict(list)
for n in names:
base = n[:-1] if n.endswith('/') else n
collisions[base].append(n)

for base, variants in collisions.items():
if len(variants) > 1:
print('COLLISION', base, '->', variants)
```
Ideas de detección para Blue-team:
- Marcar APKs cuyos encabezados locales indiquen cifrado (GPBF bit 0 = 1) pero que aún se instalen/ejecuten.
- Marcar campos Extra grandes/desconocidos en las entradas core (buscar marcadores como `JADXBLOCK`).
- Marcar colisiones de ruta (`X` y `X/`) específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Referencias

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
