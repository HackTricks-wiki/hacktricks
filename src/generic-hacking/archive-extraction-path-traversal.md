# Traversal de rutas durante la extracción de archivos («Zip-Slip»)

{{#include ../banners/hacktricks-training.md}}

## Descripción general

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada incluya su propia **ruta interna**. Cuando una utilidad de extracción respeta ciegamente esa ruta, un nombre de archivo manipulado que contenga `..` o una **ruta absoluta** (p. ej., `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.  
Esta clase de vulnerabilidad se conoce ampliamente como *Zip-Slip* o **traversal de rutas durante la extracción de archivos**.<sup>[[6]](#references)</sup>

Las consecuencias van desde sobrescribir archivos arbitrarios hasta conseguir directamente **ejecución remota de código (RCE)** al colocar un payload en una ubicación de **ejecución automática**, como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo comprimido en el que uno o más encabezados de archivo contienen:
   * Secuencias de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * O **symlinks** manipulados que se resuelven fuera del directorio de destino (algo común en ZIP/TAR en *nix*). 
2. La víctima extrae el archivo comprimido con una herramienta vulnerable que confía en la ruta incrustada (o sigue los symlinks) en lugar de sanearla o forzar la extracción dentro del directorio elegido.
3. El archivo se escribe en una ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario accede a esa ruta.

### Traversal con `Path.Combine` + `ZipArchive` en .NET

Un antipatrón común en .NET consiste en combinar el destino previsto con `ZipArchiveEntry.FullName`, controlado por el **usuario**, y extraer sin normalizar la ruta:<sup>[[4]](#references)[[8]](#references)</sup>

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

- Si `entry.FullName` empieza con `..\\`, recorre directorios; si es una **absolute path**, el componente de la izquierda se descarta por completo, lo que permite una **arbitrary file write** como identidad de extracción.
- Archivo de prueba de concepto para escribir en un directorio `app` hermano, supervisado por un escáner programado:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Al dejar ese ZIP en la bandeja de entrada supervisada, se obtiene `C:\samples\app\0xdf.txt`, lo que demuestra un traversal fuera de `C:\samples\queue\` y permite primitives posteriores (p. ej., DLL hijacks).

### Raíz de extracción controlada por el usuario

Prueba también el **directorio que se pasa al extractor**, no solo los nombres de los miembros del archivo. Una aplicación puede derivar ese directorio de un título, nombre de proyecto u otro campo de la solicitud. Un valor como `../../../../app/module` puede mover la raíz de extracción fuera del área de carga antes de que el extractor procese ningún miembro. En ese caso, incluso un archivo que solo contenga el nombre base seguro `api.py` puede sobrescribir el código de la aplicación.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Este es un límite de contención distinto del Zip-Slip clásico. Valida tanto la raíz de extracción resuelta como la ruta resuelta de cada miembro. Para comprobar la raíz, puedes usar los componentes de la ruta en lugar de un prefijo de cadena:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Para una prueba segura, sube un archivo comprimido válido que contenga un archivo canary y coloca secuencias de traversal en cada campo que pueda determinar su directorio de extracción. Supervisa tanto el directorio previsto como una ruta externa desechable. Si el destino puede acceder a un módulo importado, sobrescribirlo puede convertirse en ejecución de código cuando los workers se recarguen; un error HTTP 500 o un restablecimiento de la conexión durante esa recarga no demuestra que la escritura haya fallado.<sup>[[14]](#references)[[15]](#references)</sup> Consulta también la [metodología general de carga de archivos](../pentesting-web/file-upload/).

## Primitivas avanzadas para escapar del directorio de extracción

Trata la extracción como una secuencia de mutaciones del sistema de archivos, no como comprobaciones de nombres independientes. Una entrada que parece segura al analizarse puede volverse insegura después de que un miembro anterior cree o reemplace un enlace; el mismo problema aparece cuando un extractor almacena en caché un directorio como seguro y luego cambia su tipo.<sup>[[11]](#references)</sup>

### Pivotes mediante enlaces y colisiones de entradas

* **Escritura a través de un symlink**: crea `pivot -> /tmp` y luego extrae un miembro normal como `pivot/PWNED.txt`. Si el extractor sigue el primer miembro al materializar el segundo, la escritura escapa del directorio sin que `..` aparezca en el segundo nombre.
* **Colisión TOCTOU con caché de directorios**: crea el directorio `d/sub/`, reemplaza `d/sub` por un symlink a `/tmp` y luego añade `d/sub/PWNED.txt`. Esto apunta a extractores que validan o almacenan en caché el directorio una sola vez y no vuelven a comprobarlo antes de la escritura final.
* **Lectura/sobrescritura mediante hardlink**: TAR y RAR pueden representar hardlinks. Un hardlink a un archivo existente en el host puede exponer su contenido si un componente posterior sirve el nombre extraído; en cambio, una entrada normal en colisión puede sobrescribir el inode enlazado. Esto está limitado por las reglas del mismo sistema de archivos y los permisos del sistema operativo para hardlinks.
* **Pivote preexistente o entre archivos comprimidos**: vuelve a intentarlo con un destino que no esté vacío. Un archivo comprimido puede plantar un enlace y una extracción posterior puede escribir a través de él, aunque cada archivo pase una comprobación sin estado del nombre de la cabecera.<sup>[[11]](#references)</sup>

### Colisiones por equivalencia del sistema de archivos

Compara los nombres según la semántica del sistema de archivos que los recibirá. Entre los casos diferenciales útiles se incluyen `LINK` frente a `link` en sistemas de archivos que no distinguen mayúsculas de minúsculas, las grafías Unicode NFC frente a NFD, nombres equivalentes por compatibilidad como `ﬁle` frente a `file`, miembros duplicados que cambian una ruta de directorio a symlink y barras invertidas que solo se interpretan como separadores en Windows. Prueba también nombres que incluyan ADS en NTFS. Estos casos pueden hacer que el validador vea dos rutas mientras el sistema de archivos resuelve una sola.<sup>[[5]](#references)[[11]](#references)</sup>

Por lo tanto, un corpus compacto debería probar combinaciones ordenadas de **directorio → symlink → hijo**, **symlink → archivo normal en colisión**, **hardlink → archivo normal en colisión**, mezclas de `/` y `\`, nombres absolutos o con raíz y envoltorios comprimidos como `.tar.gz`. Ejecútalo solo en una VM/contenedor desechable y supervisa tanto el destino como la ruta externa prevista para el canary.<sup>[[11]](#references)</sup>

La ambigüedad estructural específica de ZIP puede hacer que un análisis previo y el extractor real observen nombres de entradas o árboles distintos. Consulta [Confusión entre el análisis de la cabecera local y el directorio central](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) en lugar de confiar únicamente en la salida de una sola biblioteca ZIP.

## Ejemplo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows y sus componentes RAR/UnRAR para Windows no validaban los nombres de archivo durante la extracción. La vulnerabilidad utilizaba flujos de datos alternativos de NTFS (ADS) para eludir la ruta de extracción seleccionada y escribir archivos en ubicaciones no previstas.<sup>[[5]](#references)</sup>
Un archivo RAR malicioso que contenga una entrada como:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

acabaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. ESET observó que archivos LNK maliciosos se descomprimían allí y se ejecutaban cuando el usuario iniciaba sesión, lo que proporcionaba persistencia y una vía para RCE.<sup>[[5]](#references)</sup>

### Creación de un archivo PoC (Linux/Mac)

Como CVE-2025-8088 usa una ruta de traversal en un nombre ADS, utiliza un generador específico para crear el RAR y prueba la extracción únicamente en un laboratorio aislado con una versión vulnerable de WinRAR.<sup>[[5]](#references)</sup>

### Explotación observada en la práctica

ESET informó de campañas de spear-phishing de RomCom (Storm-0978/UNC2596) que adjuntaban archivos RAR que aprovechaban CVE-2025-8088 para desplegar backdoors personalizadas y facilitar operaciones de ransomware.<sup>[[5]](#references)</sup>

## Casos más recientes (2024–2026)

### Traversal de symlinks en ZIP de 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fallo**: Las entradas ZIP que eran **enlaces simbólicos** se seguían durante la extracción, lo que permitía a los atacantes salir del directorio de destino y sobrescribir rutas arbitrarias. La interacción del usuario se limita a *abrir/extraer* el archivo.<sup>[[1]](#references)</sup>
* **Afectados**: versiones de 7-Zip anteriores a la **25.00**. El fallo en el procesamiento de enlaces simbólicos se corrigió en la **25.00** (julio de 2025) y versiones posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Vía de impacto**: Sobrescribir `Start Menu/Programs/Startup` o ubicaciones desde las que se ejecutan servicios → el código se ejecuta en el siguiente inicio de sesión o reinicio del servicio.
* **Ejemplo rápido para probar la gestión de symlinks (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Este archivo contiene una entrada symlink que apunta fuera del directorio de extracción; usa un destino desechable y verifica que el extractor no la siga. Una prueba de escritura también necesita una entrada de archivo regular debajo del symlink.

### Colisión de symlink en Go mholt/archiver `Unarchive()` (CVE-2025-3445)
* **Error**: `archiver.Unarchive()` puede extraer un symlink de ZIP y luego desreferenciarlo cuando un miembro regular posterior tiene el mismo nombre, convirtiendo una escritura que aparentemente queda dentro del directorio en una escritura fuera de él.<sup>[[2]](#references)</sup>
* **Afectado**: `github.com/mholt/archiver` ≤ 3.5.1 (el proyecto ahora está obsoleto).<sup>[[2]](#references)</sup>
* **Solución**: Cambia a `mholt/archives` ≥ 0.1.0 o rechaza los enlaces y vuelve a resolver cada destino justo antes de abrirlo.<sup>[[2]](#references)</sup>
* **Generador de colisión mínimo** (luego llama a `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### Bypass del filtrado de extracción de TAR de CPython (CVE-2026-11940)

Incluso `tarfile.extractall(filter="data")` y `filter="tar"` han tenido bypasses por el orden de los enlaces. En este caso, un hardlink hacía referencia a un symlink archivado en una ruta más profunda; la extracción de fallback validaba el symlink relativo en esa ubicación profunda, pero lo recreaba en la ubicación menos profunda del hardlink, donde el mismo destino relativo escapaba. Esta es una prueba general útil: haz que la validación y la materialización discrepen sobre el directorio base o el tipo final del miembro.<sup>[[12]](#references)</sup>

### Escape del destino de hardlink en Node `tar` mediante una cadena de symlinks (GHSA-83g3-92jg-28cx)

El paquete `tar` de Node.js aceptaba en `tar.extract()` un hardlink cuyo destino parecía estar contenido léxicamente, pero se resolvía fuera de la raíz de extracción a través de dos symlinks anteriores. El ataque funciona con las opciones de extracción predeterminadas: las comprobaciones del directorio padre del destino cubrían el nombre del hardlink dentro de la raíz, mientras que el destino del hardlink se pasaba al sistema de archivos sin resolver la cadena completa para comprobar que estuviera contenido. `tar` ≤ 7.5.7 está afectado; la versión 7.5.8 corrige el problema.<sup>[[13]](#references)</sup>

El aspecto importante del fixture de prueba es la **relación ordenada** entre los miembros, no estos nombres literales:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Si la extracción se realiza correctamente, `exfil` permanece visiblemente dentro del árbol de salida, pero comparte un inode con el archivo externo elegido; leerlo filtra ese archivo y escribir en él modifica el original. Este bypass ilustra por qué no basta con comprobar solo la ruta final, eliminar los prefijos absolutos o bloquear `..` en la cabecera del hardlink: hay que validar los destinos de los enlaces después de aplicar todo el estado del sistema de archivos extraído previamente.<sup>[[13]](#references)</sup>

## Detection Tips

* **Inspección estática** – Enumera tanto los nombres de los miembros como los destinos de los enlaces. Marca `../`, `..\\`, rutas absolutas o con raíz, symlinks, hardlinks, archivos especiales, nombres duplicados, cambios de tipo y colisiones equivalentes por mayúsculas/minúsculas o Unicode. Conserva el orden de las entradas durante la revisión, porque el exploit puede depender de miembros anteriores.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalización** – Asegúrate de que el directorio padre resuelto más el nombre base final permanezcan dentro del destino resuelto (compara los componentes de la ruta, no un prefijo de cadena sin procesar). Vuelve a comprobarlo después de cada miembro anterior; una prueba única de `realpath(join(dest, name))` es vulnerable a la sustitución de enlaces y puede fallar si la hoja aún no se ha creado.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extracción en Sandbox** – Descomprime en un directorio nuevo y desechable usando un extractor con comprobaciones de rutas/enlaces simbólicos (por ejemplo, las comprobaciones de seguridad predeterminadas de bsdtar o 7-Zip ≥ 25.00) y luego verifica que el árbol resultante no contenga enlaces hacia el exterior. El aislamiento debe impedir que una evasión ya activada alcance rutas del host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Las lecturas posteriores también importan** – Un enlace simbólico o duro que permanezca puede convertirse en una primitiva de lectura arbitraria de archivos cuando un visualizador de vista previa, CDN, explorador de archivos o pipeline de paquetes abre o sirve posteriormente el nombre extraído, aunque la extracción en sí no haya creado ningún archivo externo.<sup>[[11]](#references)</sup>
* **Supervisión de endpoints** – Genera alertas cuando se escriban nuevos ejecutables en ubicaciones `Startup`/`Run`/`cron` poco después de que WinRAR/7-Zip/etc. abra un archivo comprimido.

## Mitigación y hardening

1. **Actualiza el extractor** – WinRAR 7.13+, 7-Zip 25.00+ y Node `tar` 7.5.8+ incluyen correcciones para los problemas citados de rutas, enlaces simbólicos y destinos de enlaces.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Cuando sea posible, extrae los archivos comprimidos con “**No extraer rutas**” / “**Ignorar rutas**”. Para entradas no confiables, rechaza los enlaces simbólicos, enlaces duros, dispositivos y FIFOs, salvo que la aplicación los necesite explícitamente.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrae en un **directorio nuevo y vacío**. No combines miembros no confiables con un árbol que contenga rutas que el atacante pueda reemplazar, ni reutilices un directorio creado por un archivo comprimido anterior.<sup>[[11]](#references)</sup>
4. En Unix, elimina privilegios y aísla el destino en un **chroot/espacio de nombres de montajes**; en Windows, usa **AppContainer** o un sandbox. Un análisis posterior a la extracción no es suficiente, porque la escritura fuera del destino ocurre antes del análisis.<sup>[[11]](#references)</sup>
5. En código personalizado, aplica las reglas del sistema operativo de destino para separadores, mayúsculas/minúsculas y Unicode, y valida tanto el miembro como el destino del enlace. Resuelve y abre el destino sin seguir enlaces; no separes una comprobación de contención de una operación posterior de creación/reemplazo. El validador debe usar exactamente la misma base y la misma semántica de emulación de enlaces que la ruta de escritura.<sup>[[11]](#references)[[12]](#references)</sup>

## Otros casos afectados / históricos

* 2018 – Aviso masivo de *Zip-Slip* de Snyk que afectó a muchas bibliotecas de Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal durante la extracción TAR de slugs (corregido en v0.16.3).<sup>[[7]](#references)</sup>
* Cualquier lógica de extracción personalizada que valide las cadenas de las cabeceras, pero no los destinos de los enlaces ni la ruta final del sistema de archivos usada para cada escritura.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – Traversal de ZIP con enlaces simbólicos en 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Investigación de JFrog – Zip-Slip de mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Cómo prevenir Zip Slip en .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Cadena de HTB Bruno: ZipSlip → secuestro de DLL](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Investigación de ESET – Actualiza ya las herramientas de WinRAR: RomCom y otros están explotando una vulnerabilidad zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgación pública de una vulnerabilidad crítica de sobrescritura arbitraria de archivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug es vulnerable a un ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Opciones de extracción segura de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Se informa de un exploit de prueba de concepto para CVE-2025-11001 en 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Diversión con zip-slips, tar-slips, enlaces simbólicos, enlaces duros, colisiones y más](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Anuncio de seguridad de Python – Bypass del filtro de extracción de tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [Aviso de seguridad de GitHub – Escape del destino de un enlace duro en node-tar a través de una cadena de enlaces simbólicos](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [PoC de CVE de Rhino Security Labs – Raíz de extracción SCORM controlada por el usuario](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Múltiples vulnerabilidades en Frappe LMS que conducen a la ejecución remota de código](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
