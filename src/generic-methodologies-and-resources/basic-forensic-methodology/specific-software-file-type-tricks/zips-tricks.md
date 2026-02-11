# Trucos de ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Herramientas de línea de comandos** para gestionar **zip files** son esenciales para diagnosticar, reparar y crackear archivos zip. Aquí tienes algunas utilidades clave:

- **`unzip`**: Revela por qué un archivo zip puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato zip.
- **`zipinfo`**: Lista el contenido de un zip sin extraerlos.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar archivos zip corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para brute-force de contraseñas de zip, efectiva para contraseñas de hasta alrededor de 7 caracteres.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles completos sobre la estructura y los estándares de los archivos zip.

Es crucial notar que los archivos zip protegidos por contraseña **no cifran los nombres de archivo ni los tamaños de archivo** internamente, una falla de seguridad que no comparten RAR o 7z, los cuales sí cifran esa información. Además, los archivos zip cifrados con el método antiguo ZipCrypto son vulnerables a un **plaintext attack** si existe una copia sin cifrar de un archivo comprimido. Este ataque aprovecha el contenido conocido para crackear la contraseña del zip, una vulnerabilidad detallada en el artículo de [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y explicada más a fondo en [este paper académico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Sin embargo, los archivos zip protegidos con cifrado **AES-256** son inmunes a este plaintext attack, lo que demuestra la importancia de elegir métodos de cifrado seguros para datos sensibles.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Los dropper de malware Android modernos usan metadata ZIP malformada para romper herramientas estáticas (jadx/apktool/unzip) mientras mantienen el APK instalable en el dispositivo. Los trucos más comunes son:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Síntomas:
- `jadx-gui` falla con errores como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` pide contraseña para archivos centrales del APK aunque un APK válido no puede tener `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml` cifrados:

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
Observa el General Purpose Bit Flag de los encabezados locales y centrales. Un valor revelador es el bit 0 establecido (Encryption) incluso para entradas principales:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Si un APK se instala y se ejecuta en el dispositivo pero las entradas principales aparecen "cifradas" para las herramientas, el GPBF fue manipulado.

Solución: borrar el bit 0 del GPBF en las entradas Local File Headers (LFH) y Central Directory (CD). Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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
</details>

Uso:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Ahora deberías ver `General Purpose Flag  0000` en las entradas principales y las herramientas volverán a analizar el APK.

### 2) Campos Extra grandes/personalizados para romper parsers

Los atacantes insertan campos Extra sobredimensionados e IDs extraños en las cabeceras para provocar fallos en los decompiladores. En entornos reales puedes ver marcadores personalizados (p. ej., cadenas como `JADXBLOCK`) incrustados allí.

Inspección:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Ejemplos observados: IDs desconocidos como `0xCAFE` ("Java Executable") o `0x414A` ("JA:") transportando payloads grandes.

DFIR heuristics:
- Alertar cuando los Extra fields son inusualmente grandes en entradas core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar los Extra IDs desconocidos en esas entradas como sospechosos.

Practical mitigation: reconstruir el archivo (p. ej., re-zipping los archivos extraídos) elimina los Extra fields maliciosos. Si las herramientas se niegan a extraer debido a falsa encriptación, primero limpia GPBF bit 0 como se indicó arriba, luego repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisiones de nombres de archivo/directorio (ocultando artefactos reales)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractores y decompiladores se confunden y pueden superponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres principales de APK como `classes.dex`.

Evaluación y extracción segura:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Corrección posterior a la detección programática:
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
- Señalar APKs cuyos encabezados locales indiquen cifrado (GPBF bit 0 = 1) pero se instalen/ejecuten.
- Señalar campos Extra grandes/desconocidos en las entradas core (buscar marcadores como `JADXBLOCK`).
- Señalar colisiones de rutas (`X` y `X/`) específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Otros trucos maliciosos de ZIP (2024–2025)

### Directorios centrales concatenados (evasión multi-EOCD)

Campañas de phishing recientes envían un único blob que en realidad son **dos archivos ZIP concatenados**. Cada uno tiene su propio End of Central Directory (EOCD) + central directory. Diferentes extractores analizan distintos directorios (7zip lee el primero, WinRAR el último), lo que permite a los atacantes ocultar payloads que solo algunas herramientas muestran. Esto también evade el AV de pasarela de correo que inspecciona únicamente el primer directorio.

**Comandos de triaje**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Si aparece más de un EOCD o hay advertencias "data after payload", divide el blob e inspecciona cada parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

El moderno "better zip bomb" construye un pequeño **kernel** (bloque DEFLATE altamente comprimido) y lo reutiliza mediante overlapping local headers. Cada entrada del directorio central apunta a los mismos datos comprimidos, logrando proporciones >28M:1 sin anidar archivos. Las bibliotecas que confían en los tamaños del directorio central (Python `zipfile`, Java `java.util.zip`, Info-ZIP anteriores a hardened builds) pueden ser forzadas a asignar petabytes.

**Detección rápida (duplicate LFH offsets)**
```python
# detect overlapping entries by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
i = buf.find(b'PK\x01\x02', off)
if i<0: break
rel = struct.unpack_from('<I', buf, i+42)[0]
if rel in seen:
print('OVERLAP at offset', rel)
break
seen.add(rel); off = i+4
```
**Manejo**
- Realizar un dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` y asegurarse de que los offsets aumenten estrictamente y sean únicos.
- Limitar el tamaño total descomprimido aceptado y el recuento de entradas antes de la extracción (`zipdetails -t` o un parser personalizado).
- Cuando debas extraer, hazlo dentro de un cgroup/VM con límites de CPU y disco (evitar crashes por inflación no acotada).

---

## Referencias

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
