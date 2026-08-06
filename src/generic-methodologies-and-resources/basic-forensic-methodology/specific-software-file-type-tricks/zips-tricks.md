# Trucos de ZIPs

{{#include ../../../banners/hacktricks-training.md}}

Las **herramientas de línea de comandos** para gestionar **archivos zip** son esenciales para diagnosticar, reparar y crackear archivos zip. Estas son algunas utilidades clave:<sup>[[1]](#references)</sup>

- **`unzip`**: Revela por qué un archivo zip puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato de archivo zip.
- **`zipinfo`**: Muestra el contenido de un archivo zip sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar archivos zip dañados.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para crackear por fuerza bruta contraseñas de zip, eficaz con contraseñas de hasta aproximadamente 7 caracteres.

La [especificación del formato de archivo Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona información exhaustiva sobre la estructura y los estándares de los archivos zip.<sup>[[4]](#references)</sup>

Es crucial señalar que los archivos zip protegidos con contraseña **no cifran los nombres de archivo ni los tamaños de los archivos** contenidos en ellos, un fallo de seguridad que no comparten los archivos RAR o 7z, que sí cifran esta información. Además, los archivos zip cifrados con el método ZipCrypto antiguo son vulnerables a un **plaintext attack** si existe una copia sin cifrar de un archivo comprimido.<sup>[[1]](#references)</sup> Este ataque utiliza el contenido conocido para crackear la contraseña del zip; la vulnerabilidad se describe en el [artículo de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y se explica con más detalle en [este artículo académico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Sin embargo, los archivos zip protegidos con cifrado **AES-256** son inmunes a este plaintext attack, lo que demuestra la importancia de elegir métodos de cifrado seguros para los datos sensibles.<sup>[[1]](#references)</sup>

---

## Trucos anti-reversing en APKs mediante la manipulación de las cabeceras ZIP

Los droppers de malware modernos para Android utilizan metadatos ZIP malformados para romper herramientas de análisis estático (jadx/apktool/unzip) y mantener el APK instalable en el dispositivo. Los trucos más comunes son:<sup>[[2]](#references)</sup>

- Cifrado falso estableciendo el bit 0 del ZIP General Purpose Bit Flag (GPBF)
- Abuso de campos Extra grandes/personalizados para confundir a los parsers
- Colisiones entre nombres de archivos/directorios para ocultar artefactos reales (por ejemplo, un directorio llamado `classes.dex/` junto al `classes.dex` real)

### 1) Cifrado falso (bit 0 del GPBF establecido) sin criptografía real

Síntomas:
- `jadx-gui` falla con errores como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita una contraseña para archivos principales del APK, aunque un APK válido no puede tener `classes*.dex`, `resources.arsc` o `AndroidManifest.xml` cifrados:

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
Observa el General Purpose Bit Flag de las cabeceras locales y centrales. Un valor revelador es el bit 0 activado (Encryption), incluso para las entradas principales:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Si un APK se instala y ejecuta en el dispositivo, pero las entradas principales aparecen "cifradas" para las herramientas, el GPBF fue manipulado.

Corrígelo borrando el bit 0 del GPBF tanto en las cabeceras de archivo local (LFH) como en las entradas del directorio central (CD). Patcher mínimo de bytes:

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

Los atacantes introducen campos Extra sobredimensionados e IDs inusuales en las cabeceras para hacer fallar los decompilers. En entornos reales puedes encontrar marcadores personalizados (por ejemplo, cadenas como `JADXBLOCK`) incrustados allí.

Inspección:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Ejemplos observados: IDs desconocidos como `0xCAFE` ("Java Executable") o `0x414A` ("JA:") que contienen payloads grandes.

Heurísticas de DFIR:
- Generar una alerta cuando los campos Extra sean inusualmente grandes en entradas principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar los IDs Extra desconocidos en esas entradas como sospechosos.

Mitigación práctica: reconstruir el archivo (por ejemplo, volver a comprimir los archivos extraídos) elimina los campos Extra maliciosos. Si las herramientas se niegan a extraer debido a un cifrado falso, primero elimina el bit 0 del GPBF como se indicó anteriormente y, después, vuelve a empaquetar:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisiones de nombres de archivos/directorios (ocultando artefactos reales)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractores y decompiladores se confunden y pueden superponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres principales de APK como `classes.dex`.

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
Ideas de detección para Blue-team:
- Marcar los APK cuyos headers locales indiquen encryption (GPBF bit 0 = 1) pero que se instalen o ejecuten.
- Marcar campos Extra grandes o desconocidos en entradas principales (buscar marcadores como `JADXBLOCK`).
- Marcar colisiones de rutas (`X` y `X/`) específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Otros trucos maliciosos de ZIP (2024–2026)

### Directorios central concatenados (evasión mediante múltiples EOCD)

Las campañas recientes de phishing distribuyen un único blob que en realidad son **dos archivos ZIP concatenados**. Cada uno tiene su propio End of Central Directory (EOCD) + directorio central. Distintos extractores analizan directorios diferentes (7zip lee el primero y WinRAR el último), lo que permite a los atacantes ocultar payloads que solo muestran algunas herramientas. Esto también evade el AV básico de los mail gateways que inspecciona únicamente el primer directorio.<sup>[[5]](#references)[[6]](#references)</sup>

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

Las construcciones modernas de **better zip bomb** crean un pequeño **kernel** (bloque DEFLATE altamente comprimido) y lo reutilizan mediante local headers superpuestos. Cada entrada del central directory apunta a los mismos datos comprimidos, logrando ratios de >28M:1 sin anidar archives. Las libraries que confían en los tamaños del central directory (`zipfile` de Python, `java.util.zip` de Java, Info-ZIP antes de las builds hardened) pueden verse obligadas a asignar petabytes.<sup>[[7]](#references)[[8]](#references)</sup>

**Detección rápida (offsets LFH duplicados)**
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
- Realiza un recorrido de prueba: `zipdetails -v file.zip | grep -n "Rel Off"` y asegúrate de que los offsets sean estrictamente crecientes y únicos.
- Limita el tamaño total sin comprimir y el número de entradas aceptados antes de la extracción (`zipdetails -t` o un parser personalizado).
- Cuando debas extraer, hazlo dentro de un cgroup/VM con límites de CPU y disco (evita crashes por inflación sin límites).

---

### Confusión entre el parser del encabezado local y el del directorio central

Investigaciones recientes sobre differential-parser han demostrado que la ambigüedad de ZIP sigue siendo explotable en toolchains modernas. La idea principal es sencilla: algunos programas confían en el **Local File Header (LFH)**, mientras que otros confían en el **Central Directory (CD)**, por lo que un mismo archivo puede presentar diferentes nombres de archivo, rutas, comentarios, offsets o conjuntos de entradas según la herramienta utilizada.<sup>[[9]](#references)</sup>

Usos ofensivos prácticos:
- Hacer que un filtro de upload, un pre-scan de AV o un validador de paquetes vea un archivo benigno en el CD, mientras que el extractor respeta un nombre/ruta LFH diferente.
- Abusar de nombres duplicados, entradas presentes solo en una de las estructuras o metadatos de ruta Unicode ambiguos (por ejemplo, Info-ZIP Unicode Path Extra Field `0x7075`) para que diferentes parsers reconstruyan árboles distintos.
- Combinar esto con path traversal para convertir una vista "inofensiva" del archivo en un write-primitive durante la extracción. Para el lado de la extracción, consulta [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triage de DFIR:
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
Complétalo con:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurísticas:
- Rechaza o aísla los archivos con nombres LFH/CD no coincidentes, nombres de archivo duplicados, múltiples registros EOCD o bytes finales después del EOCD final.<sup>[[10]](#references)</sup>
- Trata los ZIP que utilicen campos extra inusuales de rutas Unicode o comentarios incoherentes como sospechosos si distintas herramientas no coinciden en el árbol extraído.<sup>[[9]](#references)</sup>
- Si el análisis es más importante que conservar los bytes originales, vuelve a empaquetar el archivo con un parser estricto después de extraerlo en un sandbox y compara la lista de archivos resultante con los metadatos originales.

Esto es importante más allá de los ecosistemas de paquetes: la misma clase de ambigüedad puede ocultar payloads a mail gateways, static scanners y custom ingestion pipelines que hacen un "peek" del contenido de los ZIP antes de que otro extractor procese el archivo.

---



## Referencias

- [1] [Guía de campo de CTF Forensics (blog de Mike, categoría CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather - Parte 1 - Un dropper multietapa (anti-reversing de APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script de Archive::Zip)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Especificación del formato de archivo ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [La estructura flexible de los archivos ZIP explotada para ocultar malware sin ser detectado (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers entierran malware en un nuevo ataque contra archivos ZIP - central directories de ZIP concatenados](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Un zip bomb mejor (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Comprendiendo las Zip Bombs: construcción del kernel con overlapping/quoted-overlap](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mi ZIP no es tu ZIP: identificación y explotación de brechas semánticas entre parsers de ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prevención de ataques de confusión de parsers de ZIP contra instaladores de paquetes Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Ataques contra ZIP con plaintext conocido reducido (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: cracking de archivos ZIP](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
