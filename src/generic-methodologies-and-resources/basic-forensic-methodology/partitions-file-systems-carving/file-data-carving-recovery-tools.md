# Herramientas de carving y recuperación de archivos/datos

{{#include ../../../banners/hacktricks-training.md}}

## Herramientas de carving y recuperación

Haz siempre carving de una **copia verificada**, nunca del dispositivo original. Consulta [Adquisición y montaje de imágenes](../image-acquisition-and-mount.md) para conocer los flujos de trabajo de adquisición de solo lectura y hash.

Más herramientas en [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

La herramienta más común en análisis forense para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que procese el archivo para encontrar archivos «ocultos». Ten en cuenta que Autopsy está diseñado para admitir imágenes de disco y otros tipos de imágenes, pero no archivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** es una herramienta para analizar archivos binarios y encontrar contenido incrustado. **Binwalk v3** es una reescritura en Rust que incluye extracción automática (`-e`), carving sin procesar de objetos conocidos y desconocidos (`-c`), análisis recursivo (Matryoshka) (`-M`) e hilos de trabajo configurables. El proyecto recomienda su compilación Docker cuando se necesitan todos los extractores externos; `cargo install binwalk` instala la CLI de Rust, pero no esas dependencias externas.<sup>[[11]](#references)</sup>

**Comandos útiles de v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

La receta heredada de v2 `--dd='.*'` **no** es el equivalente de v3 a `-c`; primero comprueba `binwalk --version` cuando sigas comandos antiguos de CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Nota de seguridad** – Las versiones **2.1.2b a 2.3.3** están afectadas por una vulnerabilidad de **Path Traversal** (CVE-2022-4510); el aviso no indica ninguna versión de pip con el parche. Evita extraer muestras no confiables con versiones afectadas o aísla la herramienta en un contenedor o con un UID sin privilegios.<sup>[[4]](#references)</sup>

### Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo quieres buscar algunos archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará los tipos de archivo configurados de forma predeterminada.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** es otra herramienta que se puede usar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, tendrás que descomentar en el archivo de configuración (_/etc/scalpel/scalpel.conf_) los tipos de archivo que quieras extraer.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Carving fragmentado con Scalpel3

Cuando la recuperación basada primero en metadatos y los programas de carving contiguo dejan archivos divididos incompletos, **Scalpel3** puede volver a ensamblar formatos compatibles mediante validadores de archivos/bloques. Su base de código es distinta de la del comando heredado `scalpel` mencionado arriba. Primero, crea el blockmap requerido con el **mismo tamaño de bloque** usado para el carving; si se conoce, usa el tamaño de clúster del sistema de archivos obtenido con `fsstat`, o determina un valor justificable antes de analizar una imagen de partición. Ejecútalo solo sobre una copia verificada y guarda la salida en un volumen separado.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Reemplaza `4096` por el tamaño de bloque seleccionado. `-w` conserva los candidatos **PROMISING**, además de los validados, y `-b` escribe vectores de bloques para ayudar a comprobar las disposiciones reconstruidas. Un archivo en PROMISING, o uno con una extensión conocida, no demuestra que se haya recuperado por completo; valida el contenido antes de usarlo.<sup>[[13]](#references)[[14]](#references)</sup> Para localizar particiones eliminadas o espacios antes de realizar el carving, consulta [Finding data outside listed partitions](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Esta herramienta viene incluida en kali, pero puedes encontrarla aquí: <https://github.com/simsong/bulk_extractor>

Bulk Extractor puede analizar una imagen de evidencia y realizar el carving de **fragmentos pcap**, **artefactos de red (URLs, dominios, IPs, MACs, correos electrónicos)** y muchos otros objetos **en paralelo mediante varios scanners**.

La versión 2.1.1 documenta una compilación con Autotools y la configuración `-S jpeg_carve_mode=2` para realizar el carving de todos los archivos JPEG contiguos.<sup>[[2]](#references)</sup>

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

El `bulk_diff.py` incluido compara dos ejecuciones de `bulk_extractor`, mientras que `bulk_extractor_reader.py` lee los archivos de informes y de características.<sup>[[3]](#references)</sup>

### PhotoRec

Puedes encontrarlo en <https://www.cgsecurity.org/wiki/TestDisk_Download>

Incluye versiones GUI y CLI. Puedes seleccionar los **tipos de archivo** que quieres que PhotoRec busque.

![Ejecuta todos los scanners, recupera JPEGs de forma agresiva y genera un bodyfile - PhotoRec: Incluye versiones GUI y CLI. Puedes seleccionar los tipos de archivo que quieres que PhotoRec busque](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (primero los metadatos)

Antes de recuperar datos mediante firmas sin procesar, prueba la recuperación teniendo en cuenta el sistema de archivos cuando los metadatos del volumen aún se puedan analizar. De forma predeterminada, `tsk_recover` solo exporta archivos no asignados; `-a` selecciona los archivos asignados y `-e` exporta ambos. Para una imagen de disco completa, pasa a `-o` el **sector inicial** de la partición indicado por `mmls` (no lo conviertas a bytes). Si la entrada ya es una imagen de partición, omite `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Este proceso puede conservar nombres y rutas derivados del sistema de archivos que el carving de cabeceras/pies no puede conservar; ejecuta Foremost, Scalpel o PhotoRec después para las entradas cuyos metadatos falten o no sean utilizables.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (creación de imágenes de unidades defectuosas)

Cuando una unidad física está inestable, lo recomendable es **crear primero una imagen** y ejecutar las herramientas de carving solo sobre ella. `ddrescue` (proyecto GNU) se centra en copiar de forma fiable discos dañados y mantener un registro de los sectores ilegibles.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

La opción **`--cluster-size`** controla cuántos sectores se copian a la vez; los valores más pequeños pueden ayudar con unidades lentas.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (recuperación de archivos eliminados en EXT 3/4)

Si el sistema de archivos de origen está basado en Linux EXT, quizá puedas recuperar archivos eliminados recientemente **sin hacer carving completo**; estas herramientas basadas en el journal funcionan en un sistema de archivos desmontado o en una imagen de solo lectura.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Nota de compatibilidad** – ext4magic está abandonado; la página del proyecto advierte que los sistemas de archivos actuales ya no son compatibles con él.<sup>[[10]](#references)</sup>

> 🛈 Si el sistema de archivos se montó después de la eliminación, es posible que los bloques de datos ya se hayan reutilizado; en ese caso, sigue siendo necesario realizar carving adecuado (Foremost/Scalpel).

### binvis

Consulta el [código](https://code.google.com/archive/p/binvis/) y la [herramienta de la página web](https://binvis.io/#/).

#### Características de BinVis

- **Visor de estructuras** visual e interactivo
- Múltiples gráficos para distintos puntos de interés
- Enfoque en partes de una muestra
- **Visualización de cadenas y recursos**, por ejemplo, en ejecutables PE o ELF
- Obtención de **patrones** para criptoanálisis de archivos
- **Detección** de algoritmos de empaquetado o codificación
- **Identificación** de esteganografía mediante patrones
- **Comparación visual** de binarios

BinVis es un excelente **punto de partida para familiarizarse con un objetivo desconocido** en un escenario de black-boxing.

## Herramientas específicas para carving de datos

### FindAES

Busca claves AES mediante la búsqueda de sus calendarios de claves. Puede encontrar claves de 128, 192 y 256 bits, como las que usan TrueCrypt y BitLocker.

Descárgalo [aquí](https://sourceforge.net/projects/findaes/).

### YARA-X (clasificación inicial de artefactos extraídos)

[YARA-X](https://github.com/VirusTotal/yara-x) es una reescritura de YARA en Rust presentada en 2024; VirusTotal informa que algunas reglas con expresiones regulares y bucles complejos pueden ejecutarse significativamente más rápido.<sup>[[5]](#references)</sup> Su CLI se llama `yr`, y el comando `scan` admite análisis recursivos, un número de hilos y salida de metadatos.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Herramientas complementarias

Puedes usar [**viu** ](https://github.com/atanq/viu) para ver imágenes desde la terminal.  \
Puedes usar la herramienta de línea de comandos de Linux **pdftotext** para convertir un PDF en texto y leerlo.







## References

- [1] [Notas de la versión 4.21 de Autopsy](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README de bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README de las herramientas de Python de bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal en binwalk (CVE-2022-4510) - Base de datos de avisos de GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA ha muerto, larga vida a YARA-X - Blog de VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Comandos de CLI de YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manual de GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manual de ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Estado del proyecto ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README de Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: manual de tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [README de Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Manual de Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Flujo de trabajo de pruebas de Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
