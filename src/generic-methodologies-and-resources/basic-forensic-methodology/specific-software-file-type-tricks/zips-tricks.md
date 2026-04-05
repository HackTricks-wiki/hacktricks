# Trucos para ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Herramientas de línea de comandos** para gestionar **archivos zip** son esenciales para diagnosticar, reparar y romper contraseñas de zip. Aquí hay algunas utilidades clave:

- **`unzip`**: Revela por qué un archivo zip puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato zip.
- **`zipinfo`**: Lista el contenido de un zip sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar archivos zip corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para romper por fuerza bruta contraseñas de zip, efectiva para contraseñas de hasta alrededor de 7 caracteres.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles completos sobre la estructura y los estándares de los archivos zip.

Es crucial notar que los archivos zip protegidos por contraseña **no cifran los nombres de archivos ni los tamaños de archivo** internamente, una falla de seguridad que no comparten RAR o 7z, los cuales sí cifran esta información. Además, los zip cifrados con el método antiguo ZipCrypto son vulnerables a un **plaintext attack** si existe una copia sin cifrar de un archivo comprimido. Este ataque aprovecha el contenido conocido para romper la contraseña del zip, una vulnerabilidad detallada en [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y explicada más a fondo en [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Sin embargo, los zip protegidos con **AES-256** son inmunes a este plaintext attack, lo que demuestra la importancia de elegir métodos de cifrado seguros para datos sensibles.

---

## Anti-reversing tricks en APKs usando cabeceras ZIP manipuladas

Los droppers de malware Android modernos usan metadata ZIP malformada para romper herramientas estáticas (jadx/apktool/unzip) mientras mantienen el APK instalable en el dispositivo. Los trucos más comunes son:

- Fake encryption estableciendo el ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusar de Extra fields grandes/personalizados para confundir parsers
- Colisiones de nombres de archivo/directorio para ocultar artefactos reales (por ejemplo, un directorio llamado `classes.dex/` junto al real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) sin criptografía real

Síntomas:
- `jadx-gui` falla con errores como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita una contraseña para archivos core del APK aunque un APK válido no puede tener `classes*.dex`, `resources.arsc` o `AndroidManifest.xml` cifrados:

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
Observa el General Purpose Bit Flag para las cabeceras locales y centrales. Un valor revelador es que el bit 0 esté activado (Encryption) incluso para entradas core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Si un APK se instala y se ejecuta en el dispositivo pero las entradas principales aparecen "cifradas" para las herramientas, se manipuló el GPBF.

Solución: borrar el bit 0 del GPBF en ambas entradas Local File Headers (LFH) y Central Directory (CD). Minimal byte-patcher:

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
Ahora deberías ver `General Purpose Flag  0000` en las entradas principales y las herramientas volverán a parsear el APK.

### 2) Campos Extra grandes/personalizados para romper parsers

Los atacantes rellenan campos Extra sobredimensionados y IDs extraños en los headers para provocar fallos en los decompilers. In the wild puedes ver marcadores personalizados (p. ej., cadenas como `JADXBLOCK`) embebidos allí.

Inspección:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Ejemplos observados: identificadores desconocidos como `0xCAFE` ("Java Executable") o `0x414A` ("JA:") que transportan grandes cargas útiles.

Heurísticas DFIR:
- Generar alerta cuando los campos Extra sean inusualmente grandes en entradas principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerar sospechosos los IDs Extra desconocidos en esas entradas.

Mitigación práctica: reconstruir el archivo (p. ej., recomprimir los archivos extraídos con zip) elimina los campos Extra maliciosos. Si las herramientas se niegan a extraer debido a cifrado falso, primero borre el bit 0 de GPBF como se indicó arriba, luego vuelva a empaquetar:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisiones de nombres de archivo/directorio (ocultando artefactos reales)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractores y decompiladores se confunden y pueden superponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres core de APK como `classes.dex`.

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
- Señalar APKs cuyos encabezados locales indican cifrado (GPBF bit 0 = 1) pero que se instalan/ejecutan.
- Señalar campos Extra grandes/desconocidos en las entradas principales (buscar marcadores como `JADXBLOCK`).
- Señalar colisiones de ruta (`X` y `X/`) específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Otros trucos maliciosos de ZIP (2024–2026)

### Directorios centrales concatenados (evasión multi-EOCD)

Campañas recientes de phishing entregan un único blob que en realidad son **dos archivos ZIP concatenados**. Cada uno tiene su propio End of Central Directory (EOCD) + central directory. Diferentes extractores procesan distintos directorios (7zip lee el primero, WinRAR el último), permitiendo a los atacantes ocultar payloads que solo algunas herramientas muestran. Esto también evade el AV básico de la pasarela de correo que solo inspecciona el primer directorio.

**Comandos de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Si aparece más de un EOCD o hay advertencias de "data after payload", divide el blob e inspecciona cada parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

La "better zip bomb" moderna construye un pequeño **núcleo** (bloque DEFLATE altamente comprimido) y lo reutiliza mediante encabezados locales superpuestos. Cada entrada del directorio central apunta a los mismos datos comprimidos, logrando relaciones >28M:1 sin anidar archivos. Las librerías que confían en los tamaños del directorio central (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) pueden verse forzadas a asignar petabytes.

**Detección rápida (desplazamientos LFH duplicados)**
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
- Realizar una comprobación en seco: `zipdetails -v file.zip | grep -n "Rel Off"` y asegurar que los offsets son estrictamente crecientes y únicos.
- Limitar el tamaño total descomprimido aceptado y el conteo de entradas antes de la extracción (`zipdetails -t` o un parser personalizado).
- Si debes extraer, hazlo dentro de un cgroup/VM con límites de CPU y disco (evita caídas por inflación sin límites).

---

### Confusión de parser entre Local-header y central-directory

Investigaciones recientes sobre differential-parser mostraron que la ambigüedad de ZIP sigue siendo explotable en cadenas de herramientas modernas. La idea principal es simple: algunos software confían en el **Local File Header (LFH)** mientras que otros confían en el **Central Directory (CD)**, por lo que un mismo archivo puede presentar diferentes nombres de archivo, rutas, comentarios, desplazamientos (offsets) o conjuntos de entradas a distintas herramientas.

Usos ofensivos prácticos:
- Haz que un filtro de subida, un preescaneo AV, o un validador de paquetes vea un archivo benigno en el CD mientras que el extractor respeta un nombre/ruta LFH diferente.
- Abusa de nombres duplicados, entradas presentes solo en una estructura, o metadatos de ruta Unicode ambiguos (por ejemplo, Info-ZIP Unicode Path Extra Field `0x7075`) para que diferentes parsers reconstruyan árboles distintos.
- Combina esto con path traversal para convertir una vista "inofensiva" del archivo en una write-primitive durante la extracción. Para el lado de la extracción, ver [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR triage:
```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
n, e = struct.unpack_from('<HH', b, i + 26)
lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
n = struct.unpack_from('<H', b, i + 28)[0]
off = struct.unpack_from('<I', b, i + 42)[0]
cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
if off in lfh and cd != lfh[off]:
print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
i += 4
```
Falta el contenido a complementar. Por favor pega el archivo src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md o indica exactamente qué quieres que añada/complemente.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurísticas:
- Rechazar o aislar archivos con nombres LFH/CD desajustados, nombres de archivo duplicados, múltiples registros EOCD o bytes sobrantes después del EOCD final.
- Tratar a los ZIPs que usan unusual Unicode-path extra fields o comentarios inconsistentes como sospechosos si distintas herramientas discrepan sobre el árbol extraído.
- Si el análisis importa más que preservar los bytes originales, reempaqueta el archivo con un analizador estricto después de la extracción en una sandbox y compara la lista de archivos resultante con los metadatos originales.

Esto importa más allá de los ecosistemas de paquetes: la misma clase de ambigüedad puede ocultar payloads ante pasarelas de correo, escáneres estáticos y pipelines de ingestión personalizados que "echan un vistazo" al contenido de ZIPs antes de que otro extractor procese el archivo.

---



## Referencias

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
