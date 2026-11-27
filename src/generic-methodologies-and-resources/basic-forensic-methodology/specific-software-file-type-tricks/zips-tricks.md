# Trucos de ZIP

{{#include ../../../banners/hacktricks-training.md}}

Las **herramientas de línea de comandos** para administrar **archivos ZIP** son esenciales para diagnosticar, reparar y crackear archivos ZIP. Estas son algunas utilidades clave:<sup>[[1]](#references)</sup>

- **`unzip`**: Revela por qué un archivo ZIP podría no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato de archivo ZIP.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Muestra el contenido de un archivo ZIP sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intentan reparar archivos ZIP dañados.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para realizar ataques de diccionario y de fuerza bruta a contraseñas ZIP; su viabilidad depende del espacio de búsqueda de contraseñas.<sup>[[15]](#references)</sup>

La [especificación del formato de archivo Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles exhaustivos sobre la estructura y los estándares de los archivos ZIP.<sup>[[4]](#references)</sup>

Los archivos ZIP tradicionales protegidos con contraseña suelen dejar visibles los nombres y tamaños de los archivos, a diferencia de los modos de cifrado de encabezados compatibles con RAR y 7z. Un ataque de texto plano conocido contra ZipCrypto recupera **claves internas de cifrado**, no necesariamente la contraseña original; esas claves bastan para descifrar entradas cifradas con la misma contraseña.<sup>[[13]](#references)</sup> El ataque requiere conocer bytes del flujo **antes del cifrado**: para un miembro almacenado, son los bytes del archivo original, pero para un miembro DEFLATE son los bytes comprimidos, lo que podría requerir recrear exactamente el resultado de la compresión.<sup>[[13]](#references)[[14]](#references)</sup> Consulta [Ataque ZIP de texto plano conocido](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) para ver un procedimiento práctico. Para conocer los fundamentos del criptoanálisis, consulta [el artículo](https://math.ucr.edu/~mike/zipattacks.pdf) y [la guía paso a paso](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Este ataque contra ZipCrypto no se aplica a las entradas ZIP cifradas con AES.<sup>[[13]](#references)</sup>

---

## Trucos anti-reversing en APKs con encabezados ZIP manipulados

Los droppers modernos de malware para Android usan metadatos ZIP malformados para hacer fallar herramientas estáticas (jadx/apktool/unzip), sin impedir que el APK se instale en el dispositivo. Los trucos más comunes son:<sup>[[2]](#references)</sup>

- Simular el cifrado estableciendo el bit 0 del ZIP General Purpose Bit Flag (GPBF)
- Abusar de campos Extra grandes o personalizados para confundir a los parsers
- Hacer colisionar nombres de archivos y directorios para ocultar artefactos reales (p. ej., un directorio llamado `classes.dex/` junto al `classes.dex` real)

### 1) Simular el cifrado (bit 0 del GPBF activado) sin criptografía real

Síntomas:
- `jadx-gui` falla con errores como:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` solicita una contraseña para archivos principales del APK, aunque un APK válido no puede tener `classes*.dex`, `resources.arsc` ni `AndroidManifest.xml` cifrados:
  
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

Observa el indicador de bits de propósito general en los encabezados local y central. Un valor revelador es el bit 0 activado (cifrado), incluso en las entradas principales:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heurística: Si un APK se instala y se ejecuta en el dispositivo, pero las herramientas muestran las entradas principales como «encrypted», se manipuló el GPBF.

Solución: borrar el bit 0 del GPBF tanto en los Local File Headers (LFH) como en las entradas del Central Directory (CD). Patcher mínimo de bytes:

<details>
<summary>Patcher mínimo para borrar el bit GPBF</summary>

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

Solo debe cambiar el bit 0: por ejemplo, `0A09` pasa a ser `0A08`, no `0000`. Este patcher mínimo busca firmas de cabecera en bytes sin procesar, por lo que los bytes que se parezcan a una firma dentro de los datos del archivo pueden provocar coincidencias falsas; trabaja sobre una copia y confirma la lista de entradas y las cabeceras resultantes antes de usar el resultado.<sup>[[4]](#references)</sup>

### 2) Campos Extra grandes/personalizados para romper parsers

Los atacantes introducen campos Extra de tamaño excesivo e ID inusuales en las cabeceras para hacer fallar los descompiladores. En la práctica, puede que veas marcadores personalizados (p. ej., cadenas como `JADXBLOCK`) incrustados allí.

Inspección:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Ejemplos observados: IDs desconocidos como `0xCAFE` ("Java Executable") o `0x414A` ("JA:") que contienen cargas útiles grandes.<sup>[[2]](#references)</sup>

Heurísticas de DFIR:
- Genera una alerta cuando los campos Extra son inusualmente grandes en entradas principales (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considera sospechosos los IDs Extra desconocidos en esas entradas.

Mitigación práctica: reconstruir el archivo (por ejemplo, volver a comprimir los archivos extraídos) elimina los campos Extra maliciosos. Si las herramientas se niegan a extraerlo debido al cifrado falso, primero borra el bit 0 de GPBF como se indicó arriba y luego vuelve a empaquetarlo:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Colisiones de nombres de archivos/directorios (ocultación de artefactos reales)

Un ZIP puede contener tanto un archivo `X` como un directorio `X/`. Algunos extractores y descompiladores se confunden y pueden superponer u ocultar el archivo real con una entrada de directorio. Esto se ha observado con entradas que colisionan con nombres principales de APK, como `classes.dex`.

Análisis inicial y extracción segura:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

Detección programática después de la corrección:

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
- Marcar los APK cuyos encabezados locales indican cifrado (GPBF bit 0 = 1) y que, aun así, se instalan o ejecutan.
- Marcar campos Extra grandes o desconocidos en entradas principales (buscar marcadores como `JADXBLOCK`).
- Marcar colisiones de rutas (`X` y `X/`), específicamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Otros trucos maliciosos con ZIP (2024–2026)

### Directorios centrales concatenados (evasión con varios EOCD)

En una campaña de phishing de 2024, los atacantes distribuyeron un único blob que, en realidad, contenía **dos archivos ZIP concatenados**. Cada uno tenía su propio registro End of Central Directory (EOCD) y directorio central. Distintos extractores analizaban directorios diferentes (7-Zip leía el primero y WinRAR, el último), lo que permitía a los atacantes ocultar payloads que solo algunas herramientas mostraban; los escáneres que inspeccionan un solo directorio pueden pasar por alto el otro archivo.<sup>[[5]](#references)[[6]](#references)</sup>

**Comandos de triaje**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Si aparece más de un EOCD o hay advertencias de «datos después de la carga útil», divide el blob e inspecciona cada parte:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Bombas de quoted-overlap / entradas solapadas (no recursivas)

Las bombas ZIP de quoted-overlap construyen un **kernel** pequeño (un bloque DEFLATE muy comprimido) y lo reutilizan en entradas solapadas. Las variantes de solapamiento completo apuntan varias entradas del directorio central a una misma cabecera local, mientras que las variantes de quoted-overlap citan cabeceras locales dentro de los flujos DEFLATE; la construcción publicada alcanza más de 28M:1 sin archivos anidados.<sup>[[7]](#references)</sup>

**Detección rápida (desplazamientos LFH duplicados)**

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
- Realiza un recorrido de prueba: `zipdetails -v file.zip | grep -n "Local Header Offset"` y compara los offsets de los encabezados locales referenciados y los rangos de datos comprimidos; los offsets duplicados indican variantes con solapamiento total.<sup>[[7]](#references)[[8]](#references)</sup>
- Limita el tamaño total descomprimido y la cantidad de entradas aceptados antes de la extracción mediante un parser; `zipinfo -t file.zip` informa los totales, pero no aplica un límite de seguridad.<sup>[[8]](#references)</sup>
- Si debes extraer el archivo, hazlo dentro de un cgroup/VM con límites de CPU y disco (evita fallos por descompresión sin límites).<sup>[[8]](#references)</sup>

---

### Confusión entre el parser del encabezado local y el del directorio central

Investigaciones recientes sobre parsers diferenciales demostraron que la ambigüedad de ZIP sigue siendo explotable en toolchains modernos. La idea principal es simple: algunos programas confían en el **Local File Header (LFH)**, mientras que otros confían en el **Central Directory (CD)**, por lo que un mismo archivo puede mostrar distintos nombres de archivo, rutas, comentarios, offsets o conjuntos de entradas a distintas herramientas.<sup>[[9]](#references)</sup>

Usos ofensivos prácticos:
- Haz que un filtro de carga, un análisis previo de AV o un validador de paquetes detecte un archivo benigno en el CD, mientras que el extractor usa otro nombre o ruta del LFH.
- Aprovecha nombres duplicados, entradas presentes solo en una de las estructuras o metadatos de ruta Unicode ambiguos (por ejemplo, el campo extra Unicode Path de Info-ZIP `0x7075`) para que distintos parsers reconstruyan árboles diferentes.
- Combina esto con path traversal para convertir una vista de archivo «inofensiva» en una primitiva de escritura durante la extracción. Para el lado de la extracción, consulta [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triaje de DFIR:

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
- Para la ingesta de datos sensibles desde el punto de vista de la seguridad, rechaza o aísla los archivos comprimidos con nombres LFH/CD distintos, nombres de archivo duplicados, varios registros EOCD o bytes finales después del último EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Considera sospechosos los ZIP que usan campos extra de ruta Unicode inusuales o comentarios incoherentes si distintas herramientas discrepan sobre el árbol extraído.<sup>[[4]](#references)[[9]](#references)</sup>
- Si el análisis es más importante que conservar los bytes originales, vuelve a empaquetar el archivo con un parser estricto tras extraerlo en un sandbox y compara la lista de archivos resultante con los metadatos originales.

Esto importa más allá de los ecosistemas de paquetes: la misma clase de ambigüedad puede ocultar payloads a las pasarelas de correo, los escáneres estáticos y los pipelines de ingesta personalizados que «echan un vistazo» al contenido de los ZIP antes de que otro extractor procese el archivo.<sup>[[9]](#references)</sup>

---





## References

- [1] [Guía de campo de análisis forense en CTF (blog de Mike, categoría CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Parte 1 – Un dropper de varias etapas (anti-reversing de APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script de IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Especificación del formato de archivo ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [La estructura flexible de los archivos ZIP se explota para ocultar malware sin ser detectado (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Los hackers ocultan malware en un nuevo ataque con archivos ZIP: directorios centrales ZIP concatenados](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Una bomba ZIP mejorada (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Entender las bombas ZIP: construcción de kernel con solapamiento/solapamiento citado](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mi ZIP no es tu ZIP: identificación y explotación de brechas semánticas entre parsers ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Cómo evitar ataques de confusión de parsers ZIP en instaladores de paquetes de Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Ataques ZIP con texto plano conocido reducido (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: misión web realista, nivel 15 (ataque ZIP con texto plano conocido)](https://www.hackthissite.org/articles/read/793)
- [13] [Uso de bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Tutorial de bkcrack con texto plano conocido](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Repositorio de fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
