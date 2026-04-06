# Trucos de ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Herramientas de línea de comandos** para gestionar **zip files** son esenciales para diagnosticar, reparar y crackear zip files. Aquí hay algunas utilidades clave:

- **`unzip`**: Revela por qué un zip file puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato zip.
- **`zipinfo`**: Lista el contenido de un zip file sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar zip files corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para brute-force cracking de zip passwords, efectiva para passwords de hasta alrededor de 7 caracteres.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles exhaustivos sobre la estructura y estándares de los zip files.

Es crucial notar que los zip files protegidos por password **no cifran los nombres de archivo ni los tamaños de archivo** en su interior, un fallo de seguridad que no comparten RAR o 7z, los cuales cifran esa información. Además, los zip files cifrados con el método antiguo ZipCrypto son vulnerables a un **plaintext attack** si existe una copia sin cifrar de un archivo comprimido. Este ataque aprovecha el contenido conocido para crackear el password del zip, una vulnerabilidad detallada en [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y explicada en [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Sin embargo, los zip files asegurados con **AES-256** son inmunes a este plaintext attack, lo que demuestra la importancia de elegir métodos de cifrado seguros para datos sensibles.

---

## Anti-reversing tricks en APKs usando cabeceras ZIP manipuladas

Modern Android malware droppers usan metadata ZIP malformada para romper herramientas estáticas (jadx/apktool/unzip) mientras mantienen el APK instalable en el dispositivo. Los trucos más comunes son:

- Fake encryption estableciendo el ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusar de campos Extra grandes/personalizados para confundir parsers
- Colisiones de nombres de archivo/directorio para ocultar artefactos reales (por ejemplo, un directorio llamado `classes.dex/` junto al real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Síntomas:
- `jadx-gui` falla con errores como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita un password para archivos APK principales a pesar de que un APK válido no puede tener cifrados `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml`:

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
Observa el General Purpose Bit Flag para las cabeceras locales y centrales. Un valor revelador es el bit 0 establecido (Cifrado) incluso para entradas core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Si un APK se instala y se ejecuta en el dispositivo pero las entradas principales aparecen "cifradas" para las herramientas, el GPBF fue manipulado.

Solución: borrar el bit 0 del GPBF tanto en los Local File Headers (LFH) como en las entradas del Central Directory (CD). Parchador de bytes mínimo:

<details>
<summary>Parchador mínimo para borrar el bit 0 del GPBF</summary>
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

Los atacantes introducen campos Extra sobredimensionados e IDs extraños en los encabezados para hacer fallar a los decompiladores. En entornos reales puedes encontrar marcadores personalizados (p. ej., cadenas como `JADXBLOCK`) incrustados allí.

Inspección:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Ejemplos observados: IDs desconocidos como `0xCAFE` ("Ejecutable Java") o `0x414A` ("JA:") que contienen grandes payloads.

Heurísticas DFIR:
- Alertar cuando los campos Extra sean inusualmente grandes en entradas principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerar los IDs Extra desconocidos en esas entradas como sospechosos.

Mitigación práctica: reconstruir el archivo (por ejemplo, volver a comprimir los archivos extraídos) elimina los campos Extra maliciosos. Si las herramientas se niegan a extraer debido a un cifrado falso, primero limpie GPBF bit 0 como arriba, luego reempaquete:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (hiding real artifacts)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractores y decompiladores se confunden y pueden superponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres centrales de APK como `classes.dex`.

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
Posfijo de detección programática:
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
- Marcar APKs cuyos encabezados locales indican cifrado (GPBF bit 0 = 1) pero que igualmente instalan/ejecutan.
- Marcar campos Extra grandes/desconocidos en entradas principales (buscar marcadores como `JADXBLOCK`).
- Marcar colisiones de rutas (`X` y `X/`) específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Otros trucos maliciosos de ZIP (2024–2026)

### Directorios centrales concatenados (evasión multi-EOCD)

Campañas de phishing recientes distribuyen un único blob que en realidad son **dos archivos ZIP concatenados**. Cada uno tiene su propio End of Central Directory (EOCD) + central directory. Diferentes extractores analizan distintos directorios (7zip lee el primero, WinRAR el último), permitiendo a los atacantes ocultar payloads que solo algunas herramientas muestran. Esto también evade el AV básico de mail gateway que inspecciona solo el primer directorio.

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

Las "better zip bomb" modernas construyen un pequeño **kernel** (bloque DEFLATE altamente comprimido) y lo reutilizan mediante encabezados locales superpuestos. Cada entrada del directorio central apunta a los mismos datos comprimidos, logrando relaciones >28M:1 sin anidar archivos. Las bibliotecas que confían en los tamaños del directorio central (Python `zipfile`, Java `java.util.zip`, Info-ZIP antes de las compilaciones reforzadas) pueden verse forzadas a asignar petabytes.

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
- Realiza una ejecución de prueba (dry-run): `zipdetails -v file.zip | grep -n "Rel Off"` y asegúrate de que los offsets aumenten estrictamente y sean únicos.
- Limita el tamaño total descomprimido aceptado y el conteo de entradas antes de la extracción (`zipdetails -t` o un parser personalizado).
- Cuando debas extraer, hazlo dentro de un cgroup/VM con límites de CPU+disco (evita crashes por inflación no acotada).

---

### Confusión entre local-header y central-directory en parsers

Investigaciones recientes sobre differential-parsers mostraron que la ambigüedad en ZIP sigue siendo explotable en toolchains modernos. La idea principal es simple: algún software confía en los **Local File Header (LFH)** mientras que otros confían en el **Central Directory (CD)**, por lo que un mismo archivo puede presentar diferentes nombres de archivo, rutas, comentarios, offsets o conjuntos de entradas a distintas herramientas.

Usos ofensivos prácticos:
- Hacer que un filtro de upload, un pre-scan de AV o un validador de paquetes vea un archivo benigno en el CD mientras que el extractor respeta un nombre/ruta diferente del LFH.
- Abusar de nombres duplicados, entradas presentes solo en una estructura, o metadatos de ruta Unicode ambiguos (por ejemplo, Info-ZIP Unicode Path Extra Field `0x7075`) para que diferentes parsers reconstruyan árboles distintos.
- Combinar esto con path traversal para convertir una vista "inofensiva" del archivo en una write-primitive durante la extracción. Para el lado de la extracción, ver [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triaje DFIR:
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
No recibí el contenido original a complementar. Por favor pega el texto del archivo o indica exactamente qué quieres que añada (p. ej. más trucos para ZIP, ejemplos de comandos, casos forenses). En cuanto lo tenga, lo traduciré al español manteniendo exactamente el mismo markdown/HTML y las reglas que mencionaste.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurísticas:
- Rechazar o aislar los archivos con nombres LFH/CD incompatibles, nombres de archivo duplicados, múltiples registros EOCD, o bytes finales después del EOCD final.
- Tratar los ZIPs que usan campos extra de ruta Unicode inusuales o comentarios inconsistentes como sospechosos si distintas herramientas discrepan sobre el árbol extraído.
- Si el análisis importa más que preservar los bytes originales, reempaqueta el archivo con un parser estricto tras la extracción en una sandbox y compara la lista de archivos resultante con los metadatos originales.

Esto importa más allá de los ecosistemas de paquetes: la misma clase de ambigüedad puede ocultar payloads a mail gateways, static scanners y pipelines de ingestión personalizados que "peek" en los contenidos ZIP antes de que un extractor diferente procese el archivo.

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
