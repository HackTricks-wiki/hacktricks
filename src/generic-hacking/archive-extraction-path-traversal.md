# Travesía de rutas en la extracción de archivos ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Descripción general

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada incluya su propia **ruta interna**. Cuando una utilidad de extracción respeta ciegamente esa ruta, un nombre de archivo manipulado que contenga `..` o una **ruta absoluta** (por ejemplo, `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.
Esta clase de vulnerabilidad se conoce ampliamente como *Zip-Slip* o **travesía de rutas durante la extracción de archivos**.<sup>[[6]](#references)</sup>

Las consecuencias van desde sobrescribir archivos arbitrarios hasta lograr directamente **ejecución remota de código (RCE)** colocando un payload en una ubicación de **ejecución automática** como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo comprimido en el que uno o más encabezados de archivo contienen:
* Secuencias de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** manipulados que se resuelven fuera del directorio de destino (algo común en ZIP/TAR sobre *nix*).
2. La víctima extrae el archivo comprimido con una herramienta vulnerable que confía en la ruta incluida (o sigue symlinks) en lugar de sanitizarla o forzar la extracción dentro del directorio elegido.
3. El archivo se escribe en la ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario activa esa ruta.

### Travesía con `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern común en `.NET` consiste en combinar el destino previsto con `ZipArchiveEntry.FullName`, controlado por el usuario, y extraer sin normalizar la ruta:<sup>[[4]](#references)[[8]](#references)</sup>
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Si `entry.FullName` comienza con `..\\`, realiza un traversal; si es una **ruta absoluta**, el componente de la izquierda se descarta por completo, lo que permite una **escritura arbitraria de archivos** como identidad de extracción.
- Archivo de prueba de concepto para escribir en un directorio `app` hermano supervisado por un scanner programado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Introducir ese ZIP en el buzón monitorizado da como resultado `C:\samples\app\0xdf.txt`, lo que demuestra el traversal fuera de `C:\samples\queue\` y permite primitives posteriores (por ejemplo, DLL hijacks).

## Primitivas avanzadas de escape de archivos

Trata la extracción como una secuencia de mutaciones del filesystem, no como comprobaciones independientes de nombres de archivo. Una entrada que es segura al analizarse puede volverse insegura después de que un miembro anterior cree o reemplace un enlace; el mismo problema aparece cuando un extractor almacena en caché un directorio como seguro y después cambia su tipo.<sup>[[11]](#references)</sup>

### Pivots mediante enlaces y colisiones de entradas

* **Symlink write-through**: crea `pivot -> /tmp` y después extrae un miembro normal como `pivot/PWNED.txt`. Si el extractor sigue el primer miembro al materializar el segundo, la escritura escapa sin que aparezca `..` en el segundo nombre.
* **Colisión de directory-cache/TOCTOU**: emite el directorio `d/sub/`, reemplaza `d/sub` por un symlink a `/tmp` y después emite `d/sub/PWNED.txt`. Esto apunta a extractors que validan o almacenan en caché el directorio una vez y no lo vuelven a comprobar antes de la escritura final.
* **Hardlink read/overwrite**: TAR y RAR pueden representar hardlinks. Un hardlink a un archivo existente del host puede exponer su contenido si un componente posterior sirve el nombre extraído; una entrada normal en colisión puede, en cambio, sobrescribir el inode enlazado. Esto está limitado por las reglas del mismo filesystem y los permisos del sistema operativo para hardlinks.
* **Pivot preexistente o entre archivos**: vuelve a intentarlo con un destino no vacío. Un archivo puede plantar un enlace y una extracción posterior puede escribir a través de él, aunque cada archivo supere una comprobación stateless del nombre en la cabecera.<sup>[[11]](#references)</sup>

### Colisiones de equivalencia del filesystem

Compara los nombres usando la semántica del filesystem que los recibirá. Entre los casos diferenciales útiles se incluyen `LINK` frente a `link` en filesystems que no distinguen mayúsculas y minúsculas, las grafías Unicode NFC frente a NFD, nombres equivalentes por compatibilidad como `ﬁle` frente a `file`, miembros duplicados que cambian una ruta de directorio a symlink y barras inversas interpretadas como separadores únicamente en Windows. Prueba también nombres que contengan ADS en NTFS. Estos casos pueden hacer que el validador vea dos rutas mientras el filesystem resuelve una sola.<sup>[[5]](#references)[[11]](#references)</sup>

Por tanto, un corpus compacto debería probar combinaciones ordenadas de **directorio → symlink → hijo**, **symlink → archivo normal en colisión**, **hardlink → archivo normal en colisión**, mezclas de `/` y `\`, nombres absolutos o rooted y wrappers comprimidos como `.tar.gz`. Ejecútalo únicamente en una VM o container desechable y observa tanto el destino como la ruta canary externa prevista.<sup>[[11]](#references)</sup>

La ambigüedad estructural específica de ZIP puede hacer que un pre-scan y el extractor real observen nombres de entrada o árboles diferentes. Consulta [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) en lugar de confiar únicamente en la salida de una biblioteca ZIP.

## Ejemplo del mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows y sus componentes Windows RAR/UnRAR no validaban los nombres de archivo durante la extracción. La vulnerabilidad utilizaba NTFS alternate data streams (ADS) para eludir la ruta de extracción seleccionada y escribir archivos en ubicaciones no deseadas.<sup>[[5]](#references)</sup>
Un archivo RAR malicioso que contiene una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. ESET observó archivos LNK maliciosos descomprimidos allí y ejecutados durante el inicio de sesión del usuario, proporcionando persistencia y una vía hacia RCE.<sup>[[5]](#references)</sup>

### Creación de un archivo PoC (Linux/Mac)

Debido a que CVE-2025-8088 utiliza una ruta de traversal en un nombre ADS, usa un generador específico para crear el RAR y, después, prueba la extracción únicamente en un laboratorio aislado con una versión vulnerable de WinRAR.<sup>[[5]](#references)</sup>

### Explotación observada en la práctica

ESET informó sobre campañas de spear-phishing de RomCom (Storm-0978/UNC2596) que adjuntaban archivos RAR que abusaban de CVE-2025-8088 para desplegar backdoors personalizados y facilitar operaciones de ransomware.<sup>[[5]](#references)</sup>

## Casos más recientes (2024–2026)

### Traversal de symlinks en ZIP de 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Las entradas ZIP que eran **symlinks** se desreferenciaban durante la extracción, permitiendo a los atacantes escapar del directorio de destino y sobrescribir rutas arbitrarias. La interacción del usuario se limita a *abrir/extraer* el archivo.<sup>[[1]](#references)</sup>
* **Afectado**: Builds de 7-Zip anteriores a **25.00**. El fallo en el procesamiento de symlinks se corrigió en **25.00** (julio de 2025) y posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Vía de impacto**: Sobrescribir `Start Menu/Programs/Startup` o ubicaciones ejecutadas por servicios → el código se ejecuta en el siguiente inicio de sesión o reinicio del servicio.
* **Fixture rápido para el manejo de symlinks (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Este archivo contiene una entrada symlink que apunta fuera del directorio de extracción; usa un destino desechable y verifica que el extractor no lo siga. Una prueba de escritura directa también necesita una entrada de archivo regular debajo del symlink.

### Colisión de symlinks en `Unarchive()` de Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` puede extraer un symlink ZIP y después desreferenciarlo cuando un miembro regular posterior tiene el mismo nombre, convirtiendo una escritura aparentemente dentro de la raíz en una escritura fuera de ella.<sup>[[2]](#references)</sup>
* **Afectado**: `github.com/mholt/archiver` ≤ 3.5.1 (el proyecto ahora está deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Cambia a `mholt/archives` ≥ 0.1.0 o rechaza los links y vuelve a resolver cada destino inmediatamente antes de abrirlo.<sup>[[2]](#references)</sup>
* **Generador mínimo de colisión** (después llama a `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### Bypass de extracción filtrada de TAR en CPython (CVE-2026-11940)

Incluso `tarfile.extractall(filter="data")` y `filter="tar"` han tenido bypasses relacionados con el orden de los links. En este caso, un hardlink hacía referencia a un symlink archivado en una ruta más profunda; la extracción alternativa validaba el symlink relativo en esa ubicación profunda, pero lo recreaba en la ubicación más superficial del hardlink, donde el mismo destino relativo escapaba. Esta es una prueba general útil: haz que la validación y la materialización no coincidan respecto al directorio base o al tipo final del miembro.<sup>[[12]](#references)</sup>

### Escape del destino de hardlinks en Node `tar` mediante una cadena de symlinks (GHSA-83g3-92jg-28cx)

El paquete `tar` de Node.js aceptaba un hardlink cuyo destino parecía estar contenido léxicamente, pero se resolvía fuera de la raíz de extracción mediante dos symlinks anteriores. El ataque funciona con las opciones de extracción predeterminadas: las comprobaciones del directorio padre del destino cubrían el nombre del hardlink dentro de la raíz, mientras que el destino del hardlink se pasaba al filesystem sin resolver la cadena completa para comprobar la contención. `tar` ≤ 7.5.7 está afectado; 7.5.8 corrige el problema.<sup>[[13]](#references)</sup>

El fixture de prueba importante es la **relación ordenada** entre los miembros, no estos nombres literales:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Si la extracción tiene éxito, `exfil` permanece visible dentro del árbol de salida, pero comparte un inode con el archivo externo elegido; leerlo hace leak de ese archivo y escribir en él modifica el original. Este bypass ilustra por qué comprobar únicamente el pathname final, eliminar prefijos absolutos o bloquear `..` en el header del hardlink es insuficiente: valida los link targets después de aplicar todo el estado del filesystem extraído previamente.<sup>[[13]](#references)</sup>

## Consejos de detección

* **Inspección estática** – Enumera tanto los nombres de los miembros como los link targets. Marca `../`, `..\\`, rutas absolutas/raíz, symlinks, hardlinks, archivos especiales, nombres duplicados, cambios de tipo y colisiones equivalentes por mayúsculas/minúsculas o Unicode. Conserva el orden de las entradas durante la revisión porque el exploit puede depender de miembros anteriores.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Canonicalisation** – Asegúrate de que el parent resuelto más el basename final permanezcan debajo del destino resuelto (compara componentes de ruta, no un prefijo de string sin procesar). Vuelve a comprobarlo después de cada miembro anterior; una prueba única de `realpath(join(dest, name))` es vulnerable al reemplazo de links y puede fallar con un leaf aún no creado.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extracción en sandbox** – Descomprime en un directorio nuevo y desechable usando un extractor con comprobaciones de paths/symlinks (por ejemplo, las comprobaciones seguras predeterminadas de bsdtar o 7-Zip ≥ 25.00); después, verifica que el árbol resultante no contenga links hacia el exterior. El aislamiento debe impedir que un escape ya activado alcance paths del host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Las lecturas posteriores importan** – Un symlink o hardlink superviviente puede convertirse en una primitive de arbitrary-file-read cuando un previewer, CDN, file browser o package pipeline abre o sirve posteriormente el nombre extraído, incluso si la extracción no creó ningún archivo externo.<sup>[[11]](#references)</sup>
* **Monitorización de endpoints** – Genera una alerta cuando se escriban nuevos ejecutables en ubicaciones `Startup`/`Run`/`cron` poco después de que WinRAR/7-Zip/etc. abra un archivo.

## Mitigación y hardening

1. **Actualiza el extractor** – WinRAR 7.13+, 7-Zip 25.00+ y Node `tar` 7.5.8+ contienen fixes para los problemas citados de path/symlink/link-target.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Extrae los archivos con “**Do not extract paths**” / “**Ignore paths**” cuando sea posible. Para input no confiable, rechaza symbolic links, hardlinks, dispositivos y FIFOs, salvo que la aplicación los necesite explícitamente.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrae en un **directorio nuevo y vacío**. No mezcles miembros no confiables en un árbol que contenga paths que el atacante pueda reemplazar, ni reutilices un directorio preparado por un archivo anterior.<sup>[[11]](#references)</sup>
4. En Unix, elimina privilegios y aísla el destino en un **chroot/mount namespace**; en Windows, usa **AppContainer** o un sandbox. Un scan posterior a la extracción por sí solo es insuficiente porque una escritura escapada ocurre antes del scan.<sup>[[11]](#references)</sup>
5. En código personalizado, aplica las reglas de separadores/case/Unicode del sistema operativo objetivo y valida tanto el miembro como el link target. Resuelve y abre el destino sin seguir links; no separes una comprobación de containment de una operación posterior de creación/reemplazo. El validator debe usar exactamente el mismo base y la misma semántica de emulación de links que el write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Casos adicionales / históricos afectados

* 2018 – Advisory masivo de *Zip-Slip* de Snyk que afectó a muchas librerías de Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377), traversal durante la extracción de TAR en slugs (fix en v0.16.3).<sup>[[7]](#references)</sup>
* Cualquier lógica de extracción personalizada que valide strings del header, pero no los link targets ni el filesystem path final usado para cada escritura.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal de symlink ZIP en 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Investigación de JFrog – Zip-Slip de mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenir Zip Slip en .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → cadena de DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Investigación de ESET – Actualiza ahora las herramientas WinRAR: RomCom y otros explotan una vulnerabilidad zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgación pública de una vulnerabilidad crítica de arbitrary file overwrite: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerable a un ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flags de extracción segura de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit de proof-of-concept reportado para CVE-2025-11001 en 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Diversión con zip-slips, tar-slips, symlinks, hardlinks, collisions y más](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – bypass del filtro de extracción de tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – escape del target de hardlink de node-tar mediante una cadena de symlinks](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
