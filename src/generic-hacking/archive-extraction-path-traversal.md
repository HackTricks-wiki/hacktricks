# Recorrido de rutas en extracción de archivos ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Resumen

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada tenga su propia **ruta interna**. Cuando una utilidad de extracción respeta ciegamente esa ruta, un nombre de archivo manipulado que contiene `..` o una **ruta absoluta** (p. ej. `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario.
Esta clase de vulnerabilidad es ampliamente conocida como *Zip-Slip* o **recorrido de rutas en extracción de archivos**.

Las consecuencias van desde sobrescribir archivos arbitrarios hasta lograr directamente **remote code execution (RCE)** al colocar un payload en una ubicación de **auto-run**, como la carpeta *Startup* de Windows.

## Causa raíz

1. El atacante crea un archivo donde uno o más encabezados de fichero contienen:
* Secuencias de recorrido relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** creados que se resuelven fuera del directorio objetivo (común en ZIP/TAR en *nix*).
2. La víctima extrae el archivo con una herramienta vulnerable que confía en la ruta incrustada (o sigue symlinks) en lugar de sanearla o forzar la extracción dentro del directorio elegido.
3. El archivo se escribe en la ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario active esa ruta.

## Ejemplo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows (incluyendo la CLI `rar` / `unrar`, la DLL y el código fuente portable) no validaba los nombres de archivo durante la extracción.
Un archivo RAR malicioso que contenía una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta del usuario *Startup*. Tras el inicio de sesión, Windows ejecuta automáticamente todo lo que esté presente allí, proporcionando *persistente* RCE.

### Creando un archivo PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opciones usadas:
* `-ep`  – almacenar las rutas de archivos exactamente como se dan (no recortar el prefijo `./`).

Entrega `evil.rar` a la víctima e indícale que lo extraiga con una versión vulnerable de WinRAR.

### Explotación observada en entornos reales

ESET informó que las campañas de spear-phishing RomCom (Storm-0978/UNC2596) adjuntaban archivos RAR que abusaban de CVE-2025-8088 para desplegar backdoors personalizados y facilitar operaciones de ransomware.

## Casos más recientes (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symlinks** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. La interacción del usuario es solo *abrir/extraer* el archivo.
* **Afectados**: 7-Zip 21.02–24.09 (Windows & Linux builds). Corregido en **25.00** (julio de 2025) y posteriores.
* **Impact path**: Sobrescribir `Start Menu/Programs/Startup` o ubicaciones donde ejecutan servicios → el código se ejecuta en el próximo inicio de sesión o reinicio del servicio.
* **PoC rápido (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
En una versión parcheada `/etc/cron.d` no será tocado; el symlink se extrae como un enlace dentro de /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Afectado**: `github.com/mholt/archiver` ≤ 3.5.1 (proyecto ahora en desuso).
* **Solución**: Cambiar a `mholt/archives` ≥ 0.1.0 o implementar comprobaciones de ruta canónica antes de escribir.
* **Reproducción mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Consejos de detección

* **Inspección estática** – Listar las entradas del archivo y marcar cualquier nombre que contenga `../`, `..\\`, *rutas absolutas* (`/`, `C:`) o entradas de tipo *symlink* cuyo destino esté fuera del directorio de extracción.
* **Canonización** – Asegurarse de que `realpath(join(dest, name))` todavía comience con `dest`. Rechazar en caso contrario.
* **Extracción en sandbox** – Descomprimir en un directorio desechable usando un extractor *seguro* (p. ej., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) y verificar que las rutas resultantes permanezcan dentro del directorio.
* **Monitorización del endpoint** – Alertar sobre nuevos ejecutables escritos en ubicaciones `Startup`/`Run`/`cron` poco después de que se abra un archivo con WinRAR/7-Zip/etc.

## Mitigación y endurecimiento

1. **Actualizar el extractor** – WinRAR 7.13+ y 7-Zip 25.00+ implementan saneamiento de rutas/symlinks. Ambas herramientas aún carecen de actualización automática.
2. Extraer los archivos con “**Do not extract paths**” / “**Ignore paths**” cuando sea posible.
3. En Unix, bajar privilegios y montar un **chroot/namespace** antes de la extracción; en Windows, usar **AppContainer** o un sandbox.
4. Si se escribe código personalizado, normalizar con `realpath()`/`PathCanonicalize()` **antes** de crear/escribir, y rechazar cualquier entrada que escape del destino.

## Casos históricos / adicionales afectados

* 2018 – Aviso masivo *Zip-Slip* por Snyk que afectó a muchas librerías Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 traversal similar durante la fusión `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (parche en v1.2).
* Cualquier lógica de extracción personalizada que no invoque `PathCanonicalize` / `realpath` antes de escribir.

## Referencias

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
