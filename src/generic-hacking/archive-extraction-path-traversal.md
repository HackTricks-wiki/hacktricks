# Extracción de Archivos de Ruta de Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Descripción General

Muchos formatos de archivo (ZIP, RAR, TAR, 7-ZIP, etc.) permiten que cada entrada lleve su propio **ruta interna**. Cuando una utilidad de extracción respeta ciegamente esa ruta, un nombre de archivo diseñado que contenga `..` o una **ruta absoluta** (por ejemplo, `C:\Windows\System32\`) se escribirá fuera del directorio elegido por el usuario. Esta clase de vulnerabilidad es ampliamente conocida como *Zip-Slip* o **extracción de archivos de ruta de traversal**.

Las consecuencias varían desde sobrescribir archivos arbitrarios hasta lograr directamente **ejecución remota de código (RCE)** al dejar caer una carga útil en una ubicación de **auto-ejecución** como la carpeta *Inicio* de Windows.

## Causa Raíz

1. El atacante crea un archivo donde uno o más encabezados de archivo contienen:
* Secuencias de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Rutas absolutas (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. La víctima extrae el archivo con una herramienta vulnerable que confía en la ruta incrustada en lugar de sanitizarla o forzar la extracción por debajo del directorio elegido.
3. El archivo se escribe en la ubicación controlada por el atacante y se ejecuta/carga la próxima vez que el sistema o el usuario active esa ruta.

## Ejemplo del Mundo Real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows (incluyendo el CLI `rar` / `unrar`, la DLL y la fuente portátil) no validó los nombres de archivo durante la extracción. Un archivo RAR malicioso que contiene una entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
terminaría **fuera** del directorio de salida seleccionado y dentro de la carpeta *Startup* del usuario. Después del inicio de sesión, Windows ejecuta automáticamente todo lo que está presente allí, proporcionando RCE *persistente*.

### Creación de un PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opciones utilizadas:
* `-ep`  – almacenar las rutas de los archivos exactamente como se indican (no **podar** `./` al principio).

Entregue `evil.rar` a la víctima e indíquele que lo extraiga con una versión vulnerable de WinRAR.

### Explotación Observada en el Mundo

ESET informó sobre campañas de spear-phishing de RomCom (Storm-0978/UNC2596) que adjuntaron archivos RAR abusando de CVE-2025-8088 para desplegar puertas traseras personalizadas y facilitar operaciones de ransomware.

## Consejos de Detección

* **Inspección estática** – Liste las entradas del archivo y marque cualquier nombre que contenga `../`, `..\\`, *rutas absolutas* (`C:`) o codificaciones UTF-8/UTF-16 no canónicas.
* **Extracción en sandbox** – Descomprima en un directorio desechable utilizando un extractor *seguro* (por ejemplo, `patool` de Python, 7-Zip ≥ última versión, `bsdtar`) y verifique que las rutas resultantes permanezcan dentro del directorio.
* **Monitoreo de endpoints** – Alerta sobre nuevos ejecutables escritos en ubicaciones de `Startup`/`Run` poco después de que se abra un archivo por WinRAR/7-Zip/etc.

## Mitigación y Fortalecimiento

1. **Actualizar el extractor** – WinRAR 7.13 implementa una correcta sanitización de rutas. Los usuarios deben descargarlo manualmente porque WinRAR carece de un mecanismo de actualización automática.
2. Extraiga archivos con la opción **“Ignorar rutas”** (WinRAR: *Extraer → "No extraer rutas"*) cuando sea posible.
3. Abra archivos no confiables **dentro de un sandbox** o VM.
4. Implemente listas blancas de aplicaciones y restrinja el acceso de escritura del usuario a directorios de autoejecución.

## Casos Afectados / Históricos Adicionales

* 2018 – Aviso masivo de *Zip-Slip* por Snyk que afecta a muchas bibliotecas de Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 similar de recorrido durante la fusión `-ao`.
* Cualquier lógica de extracción personalizada que no llame a `PathCanonicalize` / `realpath` antes de escribir.

## Referencias

- [BleepingComputer – WinRAR zero-day explotado para plantar malware en la extracción de archivos](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [Registro de cambios de WinRAR 7.13](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Informe sobre la vulnerabilidad Zip Slip](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
