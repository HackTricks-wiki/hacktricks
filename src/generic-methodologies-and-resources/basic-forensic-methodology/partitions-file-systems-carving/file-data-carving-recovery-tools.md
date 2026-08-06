# Herramientas de carving y recuperación de archivos/datos

{{#include ../../../banners/hacktricks-training.md}}

## Herramientas de carving y recuperación

Más herramientas en [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

La herramienta más común utilizada en forensics para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que procese el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñado para admitir imágenes de disco y otros tipos de imágenes, pero no archivos simples.

> **Actualización 2024-2025**: la versión **4.21** (lanzada en febrero de 2025) añadió un **módulo de carving basado en SleuthKit v4.13** reconstruido, notablemente más rápido al trabajar con imágenes de varios terabytes, y admite la extracción en paralelo en sistemas multinúcleo. También se introdujo un pequeño wrapper de CLI (`autopsycli ingest <case> <image>`), lo que permite crear scripts para realizar carving dentro de entornos de CI/CD o laboratorios a gran escala.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** es una herramienta para analizar archivos binarios y encontrar contenido incrustado. Se puede instalar mediante `apt` y su código fuente está en [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandos útiles**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Nota de seguridad** – Las versiones **≤2.3.3** están afectadas por una vulnerabilidad de **Path Traversal** (CVE-2022-4510). Actualiza (o aísla mediante un contenedor/UID sin privilegios) antes de realizar carving de muestras no confiables.<sup>[[2]](#references)</sup>

### Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo quieres buscar algunos archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará sus tipos de archivo configurados de forma predeterminada.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** es otra herramienta que se puede utilizar para buscar y extraer **archivos incrustados en un archivo**. En este caso, tendrás que quitar los comentarios de los tipos de archivo que quieras extraer en el archivo de configuración (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Esta herramienta viene incluida en Kali, pero puedes encontrarla aquí: <https://github.com/simsong/bulk_extractor>

Bulk Extractor puede analizar una imagen de evidencia y extraer **fragmentos pcap**, **artefactos de red (URLs, dominios, IPs, MACs, correos electrónicos)** y muchos otros objetos **en paralelo mediante múltiples scanners**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Los scripts útiles de postprocesamiento (`bulk_diff`, `bulk_extractor_reader.py`) pueden eliminar artefactos duplicados entre dos imágenes o convertir los resultados a JSON para su ingesta en un SIEM.

### PhotoRec

Puedes encontrarlo en <https://www.cgsecurity.org/wiki/TestDisk_Download>

Incluye versiones GUI y CLI. Puedes seleccionar los **tipos de archivo** que quieres que PhotoRec busque.

![Ejecuta todos los scanners, extrae JPEGs de forma agresiva y genera un bodyfile - PhotoRec: Incluye versiones GUI y CLI. Puedes seleccionar los tipos de archivo que quieres que PhotoRec busque](<../../../images/image (242).png>)

### ddrescue + ddrescueview (creación de imágenes de unidades defectuosas)

Cuando una unidad física es inestable, lo recomendable es **crear primero una imagen** y ejecutar las herramientas de carving únicamente sobre ella. `ddrescue` (proyecto GNU) se centra en copiar discos defectuosos de forma fiable mientras conserva un registro de los sectores ilegibles.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
La versión **1.28** (diciembre de 2024) introdujo **`--cluster-size`**, lo que puede acelerar la creación de imágenes de SSD de gran capacidad, donde los tamaños de sector tradicionales ya no se alinean con los bloques flash.

### Extundelete / Ext4magic (undelete de EXT 3/4)

Si el sistema de archivos de origen está basado en Linux EXT, es posible que puedas recuperar archivos eliminados recientemente **sin realizar un carving completo**. Ambas herramientas funcionan directamente sobre una imagen de solo lectura:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Si el sistema de archivos se montó después de la eliminación, es posible que los bloques de datos ya se hayan reutilizado; en ese caso, todavía es necesario realizar un carving adecuado (Foremost/Scalpel).

### binvis

Consulta el [código](https://code.google.com/archive/p/binvis/) y la [herramienta de la página web](https://binvis.io/#/).

#### Características de BinVis

- **Visualizador de estructuras** activo e interactivo
- Múltiples gráficos para distintos puntos de enfoque
- Enfoque en partes de una muestra
- **Visualización de strings y recursos**, por ejemplo, en ejecutables PE o ELF
- Obtención de **patrones** para cryptanalysis en archivos
- **Detección** de algoritmos de packer o encoder
- **Identificación** de Steganography mediante patrones
- **Diffing** binario **visual**

BinVis es un excelente **punto de partida para familiarizarse con un objetivo desconocido** en un escenario de black-boxing.

## Herramientas específicas de Data Carving

### FindAES

Busca claves AES mediante la búsqueda de sus key schedules. Puede encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descarga [aquí](https://sourceforge.net/projects/findaes/).

### YARA-X (triage de artefactos recuperados)

[YARA-X](https://github.com/VirusTotal/yara-x) es una reescritura de YARA en Rust publicada en 2024. Es **10-30× más rápida** que la YARA clásica y puede utilizarse para clasificar rápidamente miles de objetos recuperados:<sup>[[3]](#references)</sup>.
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
La aceleración hace realista **auto-tag** todos los archivos recuperados mediante carving en investigaciones a gran escala.

## Herramientas complementarias

Puedes usar [**viu** ](https://github.com/atanunq/viu)para ver imágenes desde el terminal.  \
Puedes usar la herramienta de línea de comandos de linux **pdftotext** para transformar un pdf en texto y leerlo.



## Referencias

- [1] [Notas de lanzamiento de Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal en binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA ha muerto, larga vida a YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
