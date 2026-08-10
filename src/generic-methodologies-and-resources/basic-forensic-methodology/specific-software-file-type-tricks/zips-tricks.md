# Trucos con ZIPs

Las **herramientas de línea de comandos** para gestionar **zip files** son esenciales para diagnosticar, reparar y crackear zip files. Estas son algunas utilidades clave:<sup>[[1]](#references)</sup>

- **`unzip`**: Revela por qué un zip file puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato zip file.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Enumera el contenido de un zip file sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar zip files corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para crackear por fuerza bruta las contraseñas de zip files, eficaz con contraseñas de hasta aproximadamente 7 caracteres.

La [especificación del formato Zip file](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona información exhaustiva sobre la estructura y los estándares de los zip files.<sup>[[4]](#references)</sup>

Es fundamental tener en cuenta que los ZIP files tradicionales protegidos con contraseña generalmente dejan visibles los nombres y tamaños de los archivos, a diferencia de los modos de cifrado de cabeceras compatibles con RAR y 7z. Además, los ZIP files cifrados con el método antiguo ZipCrypto son vulnerables a un **plaintext attack** si existe una copia sin cifrar de un archivo comprimido.<sup>[[1]](#references)</sup> Este ataque aprovecha el contenido conocido para crackear la contraseña del ZIP, como se explica en [este artículo académico](https://math.ucr.edu/~mike/zipattacks.pdf) y se muestra en [este tutorial de Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Sin embargo, el known-plaintext attack de ZipCrypto no se aplica a las entradas protegidas con cifrado **AES-256**.<sup>[[1]](#references)</sup>

---

## Trucos anti-reversing en APKs mediante cabeceras ZIP manipuladas

Los droppers de malware modernos para Android utilizan metadatos ZIP malformados para romper las herramientas de análisis estático (jadx/apktool/unzip), manteniendo el APK instalable en el dispositivo. Los trucos más comunes son:<sup>[[2]](#references)</sup>

- Falsa encryption estableciendo el bit 0 del ZIP General Purpose Bit Flag (GPBF)
- Abuso de campos Extra grandes o personalizados para confundir a los parsers
- Colisiones entre nombres de archivos y directorios para ocultar artefactos reales (por ejemplo, un directorio llamado `classes.dex/` junto al `classes.dex` real)

### 1) Falsa encryption (bit 0 del GPBF establecido) sin crypto real

Síntomas:
- `jadx-gui` falla con errores como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita una contraseña para los archivos principales del APK, aunque un APK válido no puede tener `classes*.dex`, `resources.arsc` o `AndroidManifest.xml` cifrados:

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
Observa el General Purpose Bit Flag de los encabezados local y central. Un valor revelador es el bit 0 activado (Encryption), incluso para las entradas principales:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Si un APK se instala y se ejecuta en el dispositivo, pero las entradas principales aparecen "cifradas" para las herramientas, el GPBF fue manipulado.

Solución: borrar el bit 0 del GPBF tanto en las entradas Local File Headers (LFH) como en las del Central Directory (CD). Patcher de bytes mínimo:

<details>
<summary>Patcher mínimo para borrar el bit del GPBF</summary>
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
Ahora deberías ver `General Purpose Flag  0000` en las entradas principales, y las herramientas volverán a analizar el APK.

### 2) Campos Extra grandes/personalizados para romper parsers

Los atacantes introducen campos Extra sobredimensionados e IDs inusuales en los encabezados para hacer fallar los decompiladores. En la práctica, puedes encontrar marcadores personalizados (por ejemplo, cadenas como `JADXBLOCK`) incrustados allí.

Inspección:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Ejemplos observados: IDs desconocidos como `0xCAFE` ("Java Executable") o `0x414A` ("JA:") que contienen payloads grandes.<sup>[[2]](#references)</sup>

Heurísticas de DFIR:
- Generar una alerta cuando los campos Extra sean inusualmente grandes en entradas principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar los IDs Extra desconocidos en esas entradas como sospechosos.

Mitigación práctica: reconstruir el archivo (por ejemplo, volver a comprimir los archivos extraídos) elimina los campos Extra maliciosos. Si las herramientas se niegan a extraer debido a un cifrado falso, primero elimina el bit 0 de GPBF como se indicó anteriormente y, después, vuelve a empaquetar:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisiones de nombres de archivos/directorios (ocultación de artefactos reales)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractores y decompiladores se confunden y pueden superponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres principales de APK, como `classes.dex`.

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
Detección programática posterior a la corrección:
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
Ideas de detección para blue-team:
- Marcar los APK cuyos encabezados locales indican cifrado (GPBF bit 0 = 1) y que, aun así, se instalan o ejecutan.
- Marcar los campos Extra grandes o desconocidos en las entradas principales (buscar marcadores como `JADXBLOCK`).
- Marcar las colisiones de rutas (`X` y `X/`) específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Otros trucos maliciosos de ZIP (2024–2026)

### Directorios centrales concatenados (evasión mediante múltiples EOCD)

En una campaña de phishing de 2024, los atacantes distribuyeron un único blob que en realidad era **dos archivos ZIP concatenados**. Cada uno tenía su propio registro End of Central Directory (EOCD) y directorio central. Distintos extractores analizaban directorios diferentes (7-Zip leía el primero, mientras que WinRAR leía el último), lo que permitía a los atacantes ocultar payloads que solo algunas herramientas mostraban; los scanners que inspeccionan un solo directorio pueden pasar por alto el otro archivo.<sup>[[5]](#references)[[6]](#references)</sup>

**Comandos de triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Si aparece más de un EOCD o hay advertencias de "data after payload", divide el blob e inspecciona cada parte:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (no recursivas)

Las ZIP bombs de tipo **quoted-overlap** construyen un pequeño **kernel** (un bloque DEFLATE altamente comprimido) y lo reutilizan en varias entradas superpuestas. Las variantes de superposición completa apuntan varias entradas del directorio central a un único encabezado local, mientras que las variantes de tipo quoted-overlap incluyen encabezados locales dentro de los streams DEFLATE; la construcción publicada logra más de 28M:1 sin archives anidados.<sup>[[7]](#references)</sup>

**Detección rápida (offsets LFH duplicados)**
```python
# detect full-overlap variants by identical relative offsets
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
- Realiza un análisis en seco: `zipdetails -v file.zip | grep -n "Local Header Offset"` y compara los offsets de los encabezados locales referenciados con los rangos de datos comprimidos; los offsets duplicados indican variantes con solapamiento total.<sup>[[7]](#references)[[8]](#references)</sup>
- Limita el tamaño total descomprimido aceptado y el número de entradas antes de la extracción mediante un parser; `zipinfo -t file.zip` informa de los totales, pero no aplica ningún límite de seguridad.<sup>[[8]](#references)</sup>
- Cuando debas extraer, hazlo dentro de un cgroup/VM con límites de CPU y disco (evita crashes por inflación sin límites).<sup>[[8]](#references)</sup>

---

### Confusión entre parsers del encabezado local y del directorio central

Investigaciones recientes sobre differential-parsers demostraron que la ambigüedad de ZIP todavía puede explotarse en toolchains modernas. La idea principal es sencilla: algunos programas confían en el **Local File Header (LFH)**, mientras que otros confían en el **Central Directory (CD)**, por lo que un mismo archivo puede presentar diferentes nombres de archivo, rutas, comentarios, offsets o conjuntos de entradas a distintas herramientas.<sup>[[9]](#references)</sup>

Usos ofensivos prácticos:
- Haz que un filtro de subida, un preanálisis de AV o un validador de paquetes vea un archivo benigno en el CD, mientras que el extractor respeta un nombre o una ruta LFH diferentes.
- Abusa de nombres duplicados, entradas presentes solo en una de las estructuras o metadatos de rutas Unicode ambiguos (por ejemplo, el Info-ZIP Unicode Path Extra Field `0x7075`) para que distintos parsers reconstruyan árboles diferentes.
- Combina esto con path traversal para convertir una vista de archivo "inofensiva" en una primitiva de escritura durante la extracción. Para el lado de la extracción, consulta [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Falta el contenido que quieres complementar.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurísticas:
- Para la ingestión sensible desde el punto de vista de la seguridad, rechaza o aísla los archivos con nombres LFH/CD que no coincidan, nombres de archivo duplicados, varios registros EOCD o bytes adicionales después del EOCD final.<sup>[[9]](#references)[[10]](#references)</sup>
- Trata los ZIP que utilicen extra fields de rutas Unicode inusuales o comentarios incoherentes como sospechosos si distintas herramientas no coinciden en el árbol extraído.<sup>[[4]](#references)[[9]](#references)</sup>
- Si el análisis es más importante que conservar los bytes originales, vuelve a empaquetar el archivo con un parser estricto después de extraerlo en un sandbox y compara la lista de archivos resultante con los metadatos originales.

Esto es importante más allá de los ecosistemas de paquetes: la misma clase de ambigüedad puede ocultar payloads de mail gateways, static scanners y custom ingestion pipelines que hacen "peek" del contenido ZIP antes de que otro extractor procese el archivo.<sup>[[9]](#references)</sup>

---



## References

- [1] [Guía de campo de Forensics para CTF (blog de Mike, categoría CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Parte 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script de IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Especificación del formato de archivo ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Estructura flexible de los archivos ZIP explotada para ocultar malware sin ser detectado (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Los hackers ocultan malware en un nuevo ataque contra archivos ZIP — directorios centrales ZIP concatenados](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Una zip bomb mejor (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Comprendiendo las Zip Bombs: construcción del kernel con overlapping/quoted-overlap](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mi ZIP no es tu ZIP: identificación y explotación de brechas semánticas entre parsers ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prevención de ataques de confusión de parsers ZIP contra instaladores de paquetes Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: misión web realista, nivel 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
