# Herramientas de Carving y Recuperación de Archivos/Datos

{{#include ../../../banners/hacktricks-training.md}}

## Herramientas de Carving y Recuperación

Realiza siempre el carving sobre una **copia verificada**, no sobre el dispositivo original. Consulta [Image Acquisition & Mount](../image-acquisition-and-mount.md) para conocer los flujos de trabajo de adquisición de solo lectura y hashing.

Más herramientas en [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

La herramienta más común utilizada en forensics para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que ingiera el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñado para admitir imágenes de disco y otros tipos de imágenes, pero no archivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** es una herramienta para analizar archivos binarios y encontrar contenido incrustado. **Binwalk v3** es una reescritura en Rust con extracción automática (`-e`), carving sin procesar de objetos conocidos y desconocidos (`-c`), escaneo recursivo/Matryoshka (`-M`) y hilos de trabajo configurables. El proyecto recomienda su compilación de Docker cuando se necesitan todos los extractores externos; `cargo install binwalk` instala la CLI de Rust, pero no esas dependencias externas.<sup>[[11]](#references)</sup>

**Comandos útiles de v3**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
La receta heredada de v2 `--dd='.*'` **no** es el equivalente de v3 de `-c`; comprueba primero `binwalk --version` al seguir comandos antiguos de CTF/write-ups.<sup>[[11]](#references)</sup>

⚠️  **Nota de seguridad** – Las versiones **2.1.2b a 2.3.3** están afectadas por una vulnerabilidad de **Path Traversal** (CVE-2022-4510); el aviso no indica ninguna versión de pip parcheada. Evita extraer muestras no confiables con versiones afectadas o aísla la herramienta con un contenedor/UID sin privilegios.<sup>[[4]](#references)</sup>

### Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo quieres buscar algunos archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará sus tipos de archivo configurados de forma predeterminada.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** es otra herramienta que se puede utilizar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, tendrás que descomentar en el archivo de configuración (_/etc/scalpel/scalpel.conf_) los tipos de archivo que quieres extraer.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Esta herramienta viene incluida en Kali, pero puedes encontrarla aquí: <https://github.com/simsong/bulk_extractor>

Bulk Extractor puede analizar una imagen forense y recuperar **fragmentos pcap**, **artefactos de red (URLs, dominios, IPs, MACs, correos electrónicos)** y muchos otros objetos **en paralelo mediante múltiples scanners**.

La versión v2.1.1 documenta una compilación con Autotools y la configuración `-S jpeg_carve_mode=2` para recuperar todos los archivos JPEG contiguos.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
El `bulk_diff.py` incluido compara dos ejecuciones de bulk_extractor, mientras que `bulk_extractor_reader.py` lee los archivos de informes y de características.<sup>[[3]](#references)</sup>

### PhotoRec

Puedes encontrarlo en <https://www.cgsecurity.org/wiki/TestDisk_Download>

Incluye versiones GUI y CLI. Puedes seleccionar los **tipos de archivo** que quieres que PhotoRec busque.

![Ejecuta todos los scanners, realiza carving agresivo de JPEGs y genera un bodyfile - PhotoRec: Incluye versiones GUI y CLI. Puedes seleccionar los tipos de archivo que quieres que PhotoRec busque](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Antes de realizar raw signature carving, prueba la recuperación basada en el sistema de archivos cuando los metadatos del volumen todavía se puedan analizar. De forma predeterminada, `tsk_recover` exporta únicamente archivos no asignados; `-a` selecciona los archivos asignados y `-e` exporta ambos. Para una imagen de disco completa, pasa a `-o` el **sector inicial** de la partición obtenido mediante `mmls` (no lo conviertas a bytes). Si la entrada ya es una imagen de partición, omite `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Este proceso puede conservar nombres y rutas derivados del sistema de archivos que el carving de cabecera/pie no puede conservar; ejecuta Foremost, Scalpel o PhotoRec después para las entradas cuyos metadatos falten o no sean utilizables.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (creación de imágenes de unidades defectuosas)

Cuando una unidad física es inestable, la práctica recomendada es **crear primero una imagen** y ejecutar las herramientas de carving únicamente sobre la imagen. `ddrescue` (proyecto GNU) se centra en copiar discos dañados de forma fiable y mantener un registro de los sectores ilegibles.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
La opción **`--cluster-size`** controla cuántos sectores se copian cada vez; los valores más pequeños pueden ayudar con unidades lentas.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Si el sistema de archivos de origen está basado en Linux EXT, es posible que puedas recuperar archivos eliminados recientemente **sin realizar un carving completo**; estas herramientas basadas en journaling funcionan en un sistema de archivos desmontado o en una imagen de solo lectura.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Nota de compatibilidad** – ext4magic está abandonado; la página de su proyecto advierte que los sistemas de archivos actuales ya no son compatibles con él.<sup>[[10]](#references)</sup>

> 🛈 Si el sistema de archivos se montó después de la eliminación, es posible que los bloques de datos ya se hayan reutilizado; en ese caso, todavía se requiere un carving adecuado (Foremost/Scalpel).

### binvis

Consulta el [código](https://code.google.com/archive/p/binvis/) y la [herramienta de la página web](https://binvis.io/#/).

#### Características de BinVis

- **Visor de estructuras** visual y activo
- Múltiples gráficos para distintos puntos de enfoque
- Enfoque en partes de una muestra
- **Visualización de cadenas y recursos**, por ejemplo, en ejecutables PE o ELF
- Obtención de **patrones** para criptoanálisis de archivos
- **Detección** de algoritmos de packers o encoders
- **Identificación** de Steganography mediante patrones
- **Diferenciación binaria** visual

BinVis es un excelente **punto de partida para familiarizarse con un objetivo desconocido** en un escenario de black-boxing.

## Herramientas específicas de Data Carving

### FindAES

Busca claves AES mediante la búsqueda de sus key schedules. Puede encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descarga [aquí](https://sourceforge.net/projects/findaes/).

### YARA-X (triage de artefactos extraídos)

[YARA-X](https://github.com/VirusTotal/yara-x) es una reescritura de YARA en Rust presentada en 2024; VirusTotal informa de que algunas reglas de expresiones regulares y bucles complejos pueden ejecutarse significativamente más rápido.<sup>[[5]](#references)</sup> Su CLI se llama `yr`, y el comando `scan` admite análisis recursivos, un número de hilos y salida de metadatos.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Herramientas complementarias

Puedes usar [**viu** ](https://github.com/atanunq/viu)para ver imágenes desde la terminal.  \
Puedes usar la herramienta de línea de comandos de Linux **pdftotext** para transformar un pdf en texto y leerlo.





## References

- [1] [Notas de la versión de Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README de bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README de las herramientas de Python de bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal en binwalk (CVE-2022-4510) - Base de datos de avisos de GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA ha muerto, larga vida a YARA-X - Blog de VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Comandos de YARA-X CLI](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manual de GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manual de ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Estado del proyecto ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README de Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: manual de tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
