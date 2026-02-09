# Trucos de ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** para gestionar **archivos zip** son esenciales para diagnosticar, reparar y crackear archivos zip. Aquí tienes algunas utilidades clave:

- **`unzip`**: Revela por qué un archivo zip puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato zip.
- **`zipinfo`**: Lista el contenido de un zip sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar archivos zip corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para cracking por fuerza bruta de contraseñas de zip, efectiva para contraseñas de hasta alrededor de 7 caracteres.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles completos sobre la estructura y los estándares de los archivos zip.

Es importante destacar que los archivos zip protegidos por contraseña **no cifran los nombres de archivo ni los tamaños de archivo** en su interior, una falla de seguridad que no comparten los archivos RAR o 7z, los cuales cifran esa información. Además, los archivos zip cifrados con el método antiguo ZipCrypto son vulnerables a un **plaintext attack** si existe una copia no cifrada de un archivo comprimido. Este ataque aprovecha el contenido conocido para crackear la contraseña del zip, una vulnerabilidad detallada en el artículo de HackThis y ampliada en este artículo académico. Sin embargo, los archivos zip protegidos con cifrado **AES-256** son inmunes a este **plaintext attack**, lo que demuestra la importancia de elegir métodos de cifrado seguros para datos sensibles.

---

## Trucos anti-reversing en APKs usando cabeceras ZIP manipuladas

Los droppers de malware Android modernos usan metadata ZIP malformada para romper herramientas estáticas (jadx/apktool/unzip) mientras mantienen el APK instalable en el dispositivo. Los trucos más comunes son:

- Falsa encriptación estableciendo el ZIP General Purpose Bit Flag (GPBF) bit 0
- Abuso de campos Extra grandes/personalizados para confundir parsers
- Colisiones de nombres de archivo/directorio para ocultar artefactos reales (p. ej., un directorio llamado `classes.dex/` junto al real `classes.dex`)

### 1) Falsa encriptación (bit 0 de GPBF establecido) sin criptografía real

Síntomas:
- `jadx-gui` falla con errores como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita una contraseña para archivos principales del APK aunque un APK válido no puede tener cifrados los `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml`:

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
Mira el General Purpose Bit Flag de los encabezados local y central. Un valor revelador es el bit 0 activado (Encryption) incluso para entradas core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Si un APK se instala y se ejecuta en el dispositivo pero las entradas principales aparecen "cifradas" para las herramientas, se manipuló el GPBF.

Solución: borrar el bit 0 del GPBF tanto en los Local File Headers (LFH) como en las entradas del Central Directory (CD). Patcher de bytes mínimo:

<details>
<summary>Patcher mínimo para borrar el bit 0 del GPBF</summary>
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
Ahora deberías ver `General Purpose Flag  0000` en las entradas principales y las herramientas volverán a analizar el APK nuevamente.

### 2) Campos Extra grandes/personalizados para romper parsers

Los atacantes insertan campos Extra sobredimensionados y IDs extraños en las cabeceras para hacer tropezar a los descompiladores. En la naturaleza puedes ver marcadores personalizados (p. ej., cadenas como `JADXBLOCK`) incrustados allí.

Inspección:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Ejemplos observados: IDs desconocidos como `0xCAFE` ("Ejecutable Java") o `0x414A` ("JA:") que transportan grandes cargas útiles.

Heurísticas DFIR:
- Generar alerta cuando los campos Extra son inusualmente grandes en las entradas principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar los IDs Extra desconocidos en esas entradas como sospechosos.

Mitigación práctica: reconstruir el archivo (p. ej., recomprimir en zip los archivos extraídos) elimina los campos Extra maliciosos. Si las herramientas se niegan a extraer debido a un cifrado falso, primero limpie `GPBF bit 0` como se indicó arriba, luego vuelva a empaquetar:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisiones de nombres de archivo/directorio (ocultando artefactos reales)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractores y descompiladores se confunden y pueden superponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres principales de APK como `classes.dex`.

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
Blue-team detection ideas:
- Flag APKs cuyas cabeceras locales indican cifrado (GPBF bit 0 = 1) pero se instalan/ejecutan.
- Flag campos Extra grandes/desconocidos en entradas principales (buscar marcadores como `JADXBLOCK`).
- Flag colisiones de rutas (`X` y `X/`) específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Otros trucos maliciosos con ZIP (2024–2025)

### Directorios centrales concatenados (evasión multi-EOCD)

Campañas de phishing recientes envían un único blob que en realidad son **dos archivos ZIP concatenados**. Cada uno tiene su propio End of Central Directory (EOCD) + central directory. Diferentes extractores parsean distintos directorios (7zip lee el primero, WinRAR el último), permitiendo a los atacantes ocultar payloads que sólo algunas herramientas muestran. Esto también evade el AV del gateway de correo que inspecciona solo el primer directorio.

**Triage commands**
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

La moderna "better zip bomb" crea un pequeño **kernel** (bloque DEFLATE altamente comprimido) y lo reutiliza mediante encabezados locales superpuestos. Cada entrada del directorio central apunta a los mismos datos comprimidos, logrando relaciones >28M:1 sin anidar archivos. Las bibliotecas que confían en los tamaños del directorio central (Python `zipfile`, Java `java.util.zip`, Info-ZIP antes de las compilaciones endurecidas) pueden verse forzadas a asignar petabytes.

**Detección rápida (LFH offsets duplicados)**
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
- Realizar un recorrido de prueba: `zipdetails -v file.zip | grep -n "Rel Off"` y asegúrate de que los offsets aumenten estrictamente y sean únicos.
- Limitar el tamaño total descomprimido aceptado y el recuento de entradas antes de la extracción (`zipdetails -t` o un parser personalizado).
- Cuando debas extraer, hazlo dentro de un cgroup/VM con límites de CPU y disco (evita fallos por inflación ilimitada).

---

## Referencias

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
