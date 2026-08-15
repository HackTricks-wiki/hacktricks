# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Descripción general

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada incluya su propia **ruta interna**. Cuando una utilidad de extracción respeta ciegamente esa ruta, un nombre de archivo manipulado que contenga `..` o una **ruta absoluta** (por ejemplo, `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.
Esta clase de vulnerabilidad se conoce ampliamente como *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Las consecuencias van desde sobrescribir archivos arbitrarios hasta lograr directamente **remote code execution (RCE)** colocando un payload en una ubicación de **auto-run**, como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo comprimido en el que uno o más encabezados de archivo contienen:
* Secuencias de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** manipulados que se resuelven fuera del directorio objetivo (algo común en ZIP/TAR sobre *nix*).
2. La víctima extrae el archivo comprimido con una herramienta vulnerable que confía en la ruta incrustada (o sigue symlinks) en lugar de sanitizarla o forzar la extracción dentro del directorio elegido.
3. El archivo se escribe en la ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario activa esa ruta.

### .NET `Path.Combine` + `ZipArchive` traversal

Un anti-pattern común en .NET consiste en combinar el destino previsto con `ZipArchiveEntry.FullName`, controlado por el usuario, y extraer sin normalizar la ruta:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Si `entry.FullName` comienza con `..\\`, atraviesa; si es una **ruta absoluta**, el componente de la izquierda se descarta por completo, lo que produce una **escritura arbitraria de archivos** como identidad de extracción.
- Archive de prueba de concepto para escribir en un directorio `app` hermano supervisado por un escáner programado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Depositar ese ZIP en el inbox monitorizado da como resultado `C:\samples\app\0xdf.txt`, lo que demuestra traversal fuera de `C:\samples\queue\` y permite primitives posteriores (por ejemplo, DLL hijacks).

## Primitives avanzadas de breakout de archivos

Considera la extracción como una secuencia de mutaciones del filesystem, no como comprobaciones independientes de nombres de archivo. Una entrada que es segura al analizarse puede volverse insegura después de que un miembro anterior cree o reemplace un link; el mismo problema aparece cuando un extractor almacena en caché un directorio como seguro y posteriormente cambia su tipo.<sup>[[11]](#references)</sup>

### Pivots mediante links y colisiones de entradas

* **Symlink write-through**: crea `pivot -> /tmp` y luego extrae un miembro normal como `pivot/PWNED.txt`. Si el extractor sigue el primer miembro al materializar el segundo, la escritura escapa sin que aparezca `..` en el segundo nombre.
* **Colisión de directory-cache/TOCTOU**: emite el directorio `d/sub/`, reemplaza `d/sub` por un symlink a `/tmp` y luego emite `d/sub/PWNED.txt`. Esto apunta a extractors que validan o almacenan en caché el directorio una vez y no lo vuelven a comprobar antes de la escritura final.
* **Hardlink read/overwrite**: TAR y RAR pueden representar hardlinks. Un hardlink a un archivo existente del host puede exponer su contenido si un componente posterior sirve el nombre extraído; una entrada normal en colisión puede, en cambio, sobrescribir el inode enlazado. Esto está limitado por las reglas del mismo filesystem y los permisos del sistema operativo para hardlinks.
* **Pivot preexistente o entre archivos**: reintenta con un destino no vacío. Un archivo puede plantar un link y una extracción posterior puede escribir a través de él, aunque cada archivo pase una comprobación stateless del nombre en la cabecera.<sup>[[11]](#references)</sup>

### Colisiones de equivalencia del filesystem

Compara los nombres utilizando la semántica del filesystem que los recibirá. Entre los casos diferenciales útiles se incluyen `LINK` frente a `link` en filesystems que no distinguen mayúsculas de minúsculas, las representaciones Unicode NFC frente a NFD, nombres equivalentes por compatibilidad como `ﬁle` frente a `file`, miembros duplicados que cambian una ruta de directorio a symlink y backslashes interpretadas como separadores únicamente en Windows. También prueba nombres que contengan ADS en NTFS. Estos casos pueden hacer que el validator vea dos rutas mientras el filesystem resuelve una sola.<sup>[[5]](#references)[[11]](#references)</sup>

Por lo tanto, un corpus compacto debería probar combinaciones ordenadas de **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mezclas de `/` y `\`, nombres absolutos o rooted y wrappers comprimidos como `.tar.gz`. Ejecútalo únicamente en una VM o un container desechable y supervisa tanto el destino como la ruta canary externa prevista.<sup>[[11]](#references)</sup>

## Ejemplo del mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows y sus componentes Windows RAR/UnRAR no validaban los nombres de archivo durante la extracción. El fallo utilizaba alternate data streams (ADS) de NTFS para evadir la ruta de extracción seleccionada y escribir archivos en ubicaciones no previstas.<sup>[[5]](#references)</sup>
Un archivo RAR malicioso que contenía una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. ESET observó archivos LNK maliciosos desempaquetados allí y ejecutados al iniciar sesión el usuario, proporcionando persistence y una vía hacia RCE.<sup>[[5]](#references)</sup>

### Creación de un archivo PoC (Linux/Mac)

Debido a que CVE-2025-8088 utiliza una ruta de traversal en un nombre ADS, usa un generador diseñado específicamente para crear el RAR y, después, prueba la extracción únicamente en un laboratorio aislado con una compilación vulnerable de WinRAR.<sup>[[5]](#references)</sup>

### Explotación observada en la práctica

ESET informó sobre campañas de spear-phishing de RomCom (Storm-0978/UNC2596) que adjuntaban archivos RAR que abusaban de CVE-2025-8088 para desplegar backdoors personalizados y facilitar operaciones de ransomware.<sup>[[5]](#references)</sup>

## Casos más recientes (2024–2026)

### Traversal de symlinks en ZIP de 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Las entradas ZIP que eran **symbolic links** se desreferenciaban durante la extracción, lo que permitía a los atacantes escapar del directorio de destino y sobrescribir rutas arbitrarias. La interacción del usuario consiste simplemente en *abrir/extraer* el archivo.<sup>[[1]](#references)</sup>
* **Afectado**: Compilaciones de 7-Zip anteriores a **25.00**. El fallo de procesamiento de symbolic links se corrigió en **25.00** (julio de 2025) y versiones posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Ruta de impacto**: Sobrescribir `Start Menu/Programs/Startup` o ubicaciones donde se ejecutan servicios → el código se ejecuta en el siguiente inicio de sesión o reinicio del servicio.
* **Fixture rápido para gestionar symlinks (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Este archivo contiene una entrada symlink que apunta fuera del directorio de extracción; usa un destino desechable y verifica que el extractor no lo siga. Una prueba de write-through también necesita una entrada de archivo normal debajo del symlink.

### Colisión de symlinks en `Unarchive()` de Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` puede extraer un symlink ZIP y desreferenciarlo después cuando un miembro normal posterior tiene el mismo nombre, convirtiendo una escritura aparentemente dentro de la raíz en una escritura fuera de la raíz.<sup>[[2]](#references)</sup>
* **Afectado**: `github.com/mholt/archiver` ≤ 3.5.1 (el proyecto ahora está deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Cambia a `mholt/archives` ≥ 0.1.0 o rechaza los links y vuelve a resolver cada destino inmediatamente antes de abrirlo.<sup>[[2]](#references)</sup>
* **Generador de colisión mínimo** (después llama a `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
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

Incluso `tarfile.extractall(filter="data")` y `filter="tar"` han tenido bypasses relacionados con el orden de los links. En este caso, un hardlink hacía referencia a un symlink archivado en una ruta más profunda; la extracción de fallback validaba el symlink relativo en esa ubicación profunda, pero lo recreaba en la ubicación más superficial del hardlink, donde el mismo destino relativo escapaba. Esta es una prueba general útil: haz que la validación y la materialización no coincidan respecto al directorio base o al tipo final del miembro.<sup>[[12]](#references)</sup>

## Consejos de detección

* **Inspección estática** – Enumera tanto los nombres de los miembros como los destinos de los links. Marca `../`, `..\\`, rutas absolutas/raíz, symlinks, hardlinks, archivos especiales, nombres duplicados, cambios de tipo y colisiones equivalentes por mayúsculas/minúsculas o Unicode. Conserva el orden de las entradas durante la revisión, ya que el exploit puede depender de miembros anteriores.<sup>[[11]](#references)</sup>
* **Canonicalización** – Asegúrate de que el padre resuelto más el basename final permanezcan dentro del destino resuelto (compara componentes de ruta, no un prefijo de cadena sin procesar). Vuelve a comprobarlo después de cada miembro anterior; una prueba única de `realpath(join(dest, name))` es vulnerable a la sustitución de links y puede fallar con una hoja que todavía no se ha creado.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extracción en sandbox** – Descomprime en un directorio nuevo y desechable usando un extractor con comprobaciones de rutas/symlinks (por ejemplo, las comprobaciones seguras predeterminadas de bsdtar o 7-Zip ≥ 25.00) y, después, verifica que el árbol resultante no contenga links hacia el exterior. El aislamiento debe impedir que una escape ya activada alcance rutas del host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Las lecturas posteriores importan** – Un symlink o hardlink superviviente puede convertirse en una primitive de lectura arbitraria de archivos cuando un previewer, CDN, explorador de archivos o pipeline de paquetes abre o sirve posteriormente el nombre extraído, incluso si la extracción no creó ningún archivo externo.<sup>[[11]](#references)</sup>
* **Monitorización de endpoints** – Genera una alerta cuando se escriban nuevos ejecutables en ubicaciones `Startup`/`Run`/`cron` poco después de que WinRAR/7-Zip/etc. abra un archivo.

## Mitigación y hardening

1. **Actualiza el extractor** – WinRAR 7.13+ y 7-Zip 25.00+ incluyen fixes para los problemas de rutas/symlinks citados.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extrae archivos con “**Do not extract paths**” / “**Ignore paths**” cuando sea posible. Para entradas no confiables, rechaza symbolic links, hardlinks, dispositivos y FIFOs, salvo que la aplicación los necesite explícitamente.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrae en un **directorio nuevo y vacío**. No mezcles miembros no confiables en un árbol que contenga rutas que el atacante pueda reemplazar, y no reutilices un directorio creado por un archivo anterior.<sup>[[11]](#references)</sup>
4. En Unix, elimina privilegios y aísla el destino en un **chroot/mount namespace**; en Windows, usa **AppContainer** o un sandbox. Un análisis posterior a la extracción por sí solo es insuficiente porque una escritura externa ocurre antes del análisis.<sup>[[11]](#references)</sup>
5. En código personalizado, aplica las reglas de separadores, mayúsculas/minúsculas y Unicode del sistema operativo de destino, y valida tanto el miembro como el destino del link. Resuelve y abre el destino sin seguir links; no separes una comprobación de contención de una operación posterior de creación/reemplazo. El validador debe usar exactamente la misma base y semántica de emulación de links que la ruta de escritura.<sup>[[11]](#references)[[12]](#references)</sup>

## Casos adicionales / históricos afectados

* 2018 – Advisory masivo de *Zip-Slip* de Snyk que afectaba a muchas librerías Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377), traversal de extracción TAR en slugs (corregido en v0.16.3).<sup>[[7]](#references)</sup>
* Cualquier lógica de extracción personalizada que valide strings de cabecera, pero no los destinos de los links ni la ruta final del filesystem utilizada para cada escritura.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – Traversal de symlinks ZIP en 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Investigación de JFrog – Zip-Slip en mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenir Zip Slip en .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Cadena ZipSlip → DLL hijack de HTB Bruno](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Investigación de ESET – Actualiza ahora las herramientas de WinRAR: RomCom y otros explotan una vulnerabilidad zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgación pública de una vulnerabilidad crítica de sobrescritura arbitraria de archivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug de HashiCorp vulnerable a un ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Flags de extracción segura de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Informado un exploit Proof-of-Concept para CVE-2025-11001 en 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Diversión con zip-slips, tar-slips, symlinks, hardlinks, colisiones y más](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Bypass del filtro de extracción tarfile de CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
