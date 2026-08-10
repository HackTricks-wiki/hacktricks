# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Descripción general

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada incluya su propia **ruta interna**. Cuando una utilidad de extracción respeta ciegamente esa ruta, un nombre de archivo creado con `..` o una **ruta absoluta** (por ejemplo, `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.  
Esta clase de vulnerabilidad se conoce ampliamente como *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Las consecuencias van desde sobrescribir archivos arbitrarios hasta lograr directamente **remote code execution (RCE)** colocando un payload en una ubicación de **auto-run**, como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo donde uno o más encabezados contienen:
* Secuencias de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** creados especialmente que se resuelven fuera del directorio objetivo (común en ZIP/TAR sobre sistemas *nix*).
2. La víctima extrae el archivo con una herramienta vulnerable que confía en la ruta incorporada (o sigue symlinks) en lugar de sanitizarla u obligar a que la extracción se realice dentro del directorio elegido.
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
- Si `entry.FullName` comienza con `..\\`, realiza un traversal; si es una **ruta absoluta**, el componente de la izquierda se descarta por completo, lo que produce una **escritura arbitraria de archivos** como identidad de extracción.
- Archivo de prueba de concepto para escribir en un directorio `app` hermano supervisado por un scanner programado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Al depositar ese ZIP en la bandeja de entrada supervisada se genera `C:\samples\app\0xdf.txt`, lo que demuestra el traversal fuera de `C:\samples\queue\` y permite primitives posteriores (por ejemplo, DLL hijacks).

## Ejemplo del mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows y sus componentes Windows RAR/UnRAR no validaban los nombres de archivo durante la extracción. La vulnerabilidad utilizaba alternate data streams (ADS) de NTFS para eludir la ruta de extracción seleccionada y escribir archivos en ubicaciones no previstas.<sup>[[5]](#references)</sup>
Un archivo RAR malicioso que contenía una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. ESET observó archivos LNK maliciosos que se desempaquetaban allí y se ejecutaban cuando el usuario iniciaba sesión, proporcionando persistencia y una vía hacia RCE.<sup>[[5]](#references)</sup>

### Creación de un archivo PoC (Linux/Mac)

Debido a que CVE-2025-8088 utiliza una ruta de traversal en un nombre ADS, usa un generador diseñado específicamente para crear el RAR y, después, prueba la extracción únicamente en un lab aislado con una build vulnerable de WinRAR.<sup>[[5]](#references)</sup>

### Explotación observada in the Wild

ESET informó sobre campañas de spear-phishing de RomCom (Storm-0978/UNC2596) que adjuntaban archivos RAR abusando de CVE-2025-8088 para desplegar backdoors personalizados y facilitar operaciones de ransomware.<sup>[[5]](#references)</sup>

## Casos más recientes (2024–2025)

### Traversal de symlink en ZIP de 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Las entradas ZIP que eran **symlinks** se desreferenciaban durante la extracción, lo que permitía a los atacantes escapar del directorio de destino y sobrescribir rutas arbitrarias. La interacción del usuario consiste simplemente en *abrir/extraer* el archivo.<sup>[[1]](#references)</sup>
* **Affected**: Builds de 7-Zip anteriores a **25.00**. El flaw de procesamiento de symlinks se corrigió en **25.00** (julio de 2025) y versiones posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Sobrescribir `Start Menu/Programs/Startup` o ubicaciones donde se ejecutan servicios → el código se ejecuta en el siguiente inicio de sesión o reinicio del servicio.
* **Fixture rápido para gestionar symlinks (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Este archivo contiene una entrada symlink que apunta fuera del directorio de extracción; usa un destino desechable y verifica que el extractor no lo siga. Un test de write-through también necesita una entrada de archivo normal debajo del symlink.

### Zip-Slip de Unarchive() de Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` sigue `../` y las entradas ZIP con symlinks, escribiendo fuera de `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (el proyecto está deprecated actualmente).
* **Fix**: Cambia a `mholt/archives` ≥ 0.1.0 o implementa comprobaciones de rutas canónicas antes de escribir.
* **Reproducción mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Consejos de detección

* **Inspección estática** – Enumera las entradas del archivo y marca cualquier nombre que contenga `../`, `..\\`, *rutas absolutas* (`/`, `C:`) o entradas de tipo *symlink* cuyo destino esté fuera del directorio de extracción.
* **Canonicalización** – Asegúrate de que `realpath(join(dest, name))` permanezca dentro de `realpath(dest)` (compara los componentes de la ruta, no solo un prefijo de cadena sin procesar). Rechaza cualquier otro caso.<sup>[[3]](#references)</sup>
* **Extracción en sandbox** – Descomprime en un directorio desechable usando un extractor con comprobaciones de rutas/symlinks (por ejemplo, las comprobaciones seguras predeterminadas de bsdtar o 7-Zip ≥ 25.00) y, después, verifica que las rutas resultantes permanezcan dentro del directorio.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitorización de endpoints** – Genera una alerta cuando se escriban nuevos ejecutables en ubicaciones `Startup`/`Run`/`cron` poco después de que se abra un archivo con WinRAR/7-Zip/etc.

## Mitigación y hardening

1. **Actualiza el extractor** – WinRAR 7.13+ y 7-Zip 25.00+ contienen fixes para los problemas de rutas/symlinks citados.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extrae archivos con “**Do not extract paths**” / “**Ignore paths**” cuando sea posible.
3. En Unix, elimina privilegios y monta un **chroot/namespace** antes de la extracción; en Windows, usa **AppContainer** o un sandbox.
4. Si escribes código personalizado, normaliza con `realpath()`/`PathCanonicalize()` **antes** de crear/escribir y rechaza cualquier entrada que escape del destino.

## Casos adicionales afectados / históricos

* 2018 – Advisory masivo de *Zip-Slip* de Snyk que afectaba a muchas librerías de Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377), traversal durante la extracción TAR en slugs (corregido en v0.16.3).<sup>[[7]](#references)</sup>
* Cualquier lógica de extracción personalizada que no llame a `PathCanonicalize` / `realpath` antes de escribir.

## References

- [1] [Trend Micro ZDI-25-949 – Traversal de symlinks ZIP en 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Investigación de JFrog – Zip-Slip de mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenir Zip Slip en .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Cadena ZipSlip → DLL hijack de HTB Bruno](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Investigación de ESET – Actualiza las herramientas de WinRAR ahora: RomCom y otros explotan una vulnerabilidad zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgación pública de una vulnerabilidad crítica de sobrescritura arbitraria de archivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerable a un ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Flags de extracción segura de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Reportado exploit Proof-of-Concept para CVE-2025-11001 en 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
