# Particiones/Sistemas de archivos/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Particiones

Un disco puede contener varias **particiones**: rangos lógicos de bloques, no almacenamiento físicamente separado. Los inicios y las longitudes de las particiones se miden en **sectores lógicos**; no des por sentado que todas las imágenes usan sectores de 512 bytes, ya que también existen sectores lógicos de 4096 bytes.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

El MBR ocupa el primer sector lógico (LBA 0); sus cuatro entradas de partición de 16 bytes comienzan en el byte 446. El área anterior incluye código de arranque y puede incluir una firma del disco.<sup>[[4]](#references)</sup>\
Permite hasta **4 particiones** (como máximo **solo 1** puede estar activa/**ser de arranque**). Sin embargo, si necesitas más particiones, puedes usar **particiones extendidas**. Los últimos **dos bytes** del MBR de 512 bytes son la firma de arranque **0x55 0xAA**. Solo una partición puede marcarse como activa.\
Con sectores lógicos de 512 bytes, los campos de sector de 32 bits del MBR limitan el direccionamiento a unos **2 TiB** (2,2 TB).<sup>[[4]](#references)</sup>

![Particiones - MBR (master Boot Record): MBR permite un máximo de 2,2 TB](<../../../images/image (350).png>)

![Particiones - MBR (master Boot Record): MBR permite un máximo de 2,2 TB](<../../../images/image (304).png>)

En los **bytes 440 a 443** del MBR puedes encontrar la **Windows Disk Signature** (si se usa Windows). La letra de unidad lógica del disco duro depende de la Windows Disk Signature. Cambiar esta firma podría impedir que Windows arranque (herramienta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Particiones - MBR (master Boot Record): En los bytes 440 a 443 del MBR puedes encontrar la Windows Disk Signature (si se usa Windows). La letra de unidad lógica del disco duro...](<../../../images/image (310).png>)

**Formato**

| Offset      | Longitud   | Elemento                 |
| ----------- | ---------- | ------------------------ |
| 0 (0x00)    | 446(0x1BE) | Código de arranque       |
| 446 (0x1BE) | 16 (0x10)  | Primera partición        |
| 462 (0x1CE) | 16 (0x10)  | Segunda partición        |
| 478 (0x1DE) | 16 (0x10)  | Tercera partición        |
| 494 (0x1EE) | 16 (0x10)  | Cuarta partición         |
| 510 (0x1FE) | 2 (0x2)    | Firma 0x55 0xAA           |

**Formato del registro de partición**

| Offset    | Longitud | Elemento                                                |
| --------- | -------- | ------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Indicador de partición activa (0x80 = de arranque)      |
| 1 (0x01)  | 1 (0x01) | Cabeza inicial                                         |
| 2 (0x02)  | 1 (0x01) | Sector inicial (bits 0-5); bits superiores del cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01) | 8 bits inferiores del cilindro inicial                 |
| 4 (0x04)  | 1 (0x01) | Código de tipo de partición (0x83 = Linux)              |
| 5 (0x05)  | 1 (0x01) | Cabeza final                                           |
| 6 (0x06)  | 1 (0x01) | Sector final (bits 0-5); bits superiores del cilindro (6- 7) |
| 7 (0x07)  | 1 (0x01) | 8 bits inferiores del cilindro final                   |
| 8 (0x08)  | 4 (0x04) | Sectores anteriores a la partición (little endian)      |
| 12 (0x0C) | 4 (0x04) | Sectores de la partición                               |

Para inspeccionar una partición en una imagen MBR de disco completo, primero obtén su LBA inicial y el tamaño del sector lógico. `mount` requiere un **desplazamiento en bytes**, no un LBA; el siguiente ejemplo solo es válido para una imagen con sectores de 512 bytes cuya partición comienza en el LBA 63. Para imágenes no confiables o sistemas de archivos con journaling, usa en su lugar el procedimiento aislado y de solo lectura de [Image Acquisition & Mount](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Particiones - MBR (master Boot Record): Para montar un MBR en Linux, primero necesitas obtener el desplazamiento inicial (puedes usar fdisk y el comando p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) es un esquema común para **especificar la ubicación de bloques** de datos almacenados en dispositivos de almacenamiento informático, generalmente sistemas de almacenamiento secundario como las unidades de disco duro. LBA es un esquema de direccionamiento lineal especialmente sencillo: **los bloques se ubican mediante un índice entero**; el primer bloque es LBA 0, el segundo LBA 1, y así sucesivamente.

### GPT (GUID Partition Table)

La GUID Partition Table (GPT) almacena un GUID único para cada partición y utiliza metadatos primarios y de respaldo. Su diseño difiere del de MBR de la siguiente manera:<sup>[[4]](#references)</sup>

- **Ubicación y tamaño**: LBA 0 contiene un **MBR protector**. El encabezado GPT primario está en LBA 1; a continuación se encuentra su matriz de entradas de partición, y al final del disco están la matriz y el encabezado de respaldo. GPT usa campos LBA de 64 bits, mientras que las entradas de partición MBR usan campos LBA de 32 bits.
- **Límites de particiones**: Una matriz común de entradas de 16 KiB contiene **128 entradas de 128 bytes**, pero la cantidad de entradas se registra en el encabezado, en lugar de estar fijada por GPT. El tamaño direccionable también depende del tamaño del sector lógico (aproximadamente **9.4 ZB** con sectores de 512 bytes).<sup>[[4]](#references)</sup>
- **Nombres de partición**: Permite asignar nombres de hasta 36 caracteres Unicode a las particiones.

**Resiliencia y recuperación de datos**:

- **Redundancia**: A diferencia de MBR, GPT no limita los datos de particionado y arranque a una sola ubicación. Los replica en el disco, lo que mejora la integridad y resiliencia de los datos.
- **Comprobación de redundancia cíclica (CRC)**: Tanto el encabezado como la matriz de entradas de partición tienen un CRC32. Un CRC detecta incoherencias; no supervisa continuamente el disco ni lo repara por sí mismo. Si la copia primaria no es válida, valida la copia de respaldo en el último LBA antes de realizar cualquier recuperación en una copia de trabajo.<sup>[[4]](#references)</sup>

**MBR protector (LBA0)**:

- GPT mantiene la compatibilidad con versiones anteriores mediante un MBR protector. Esta función reside en el espacio del MBR heredado, pero está diseñada para impedir que las utilidades antiguas basadas en MBR sobrescriban por error discos GPT, protegiendo así la integridad de los datos en discos con formato GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**MBR híbrido (LBA 0 + GPT)**

[De Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

En sistemas operativos que admiten el **arranque basado en GPT mediante** servicios de BIOS en lugar de EFI, el primer sector también puede seguir utilizándose para almacenar la primera etapa del código del **bootloader**, pero **modificado** para reconocer las **particiones** **GPT**. El bootloader en el MBR no debe asumir un tamaño de sector de 512 bytes.

**Encabezado de la tabla de particiones (LBA 1)**

[De Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

El encabezado de la tabla de particiones define los bloques utilizables del disco. También define la cantidad y el tamaño de las entradas de partición que componen la tabla de particiones (desplazamientos 80 y 84 de la tabla).

| Desplazamiento | Longitud | Contenido                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Firma ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h o 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)en máquinas little-endian) |
| 8 (0x08)  | 4 bytes  | Revisión 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Tamaño del encabezado en little endian (en bytes, normalmente 5Ch 00h 00h 00h o 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) del encabezado (desde el desplazamiento +0 hasta el tamaño del encabezado) en little endian, con este campo puesto a cero durante el cálculo                             |
| 20 (0x14) | 4 bytes  | Reservado; debe ser cero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | LBA actual (ubicación de esta copia del encabezado)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | LBA de respaldo (ubicación de la otra copia del encabezado)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Primer LBA utilizable para particiones (último LBA de la tabla de particiones primaria + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Último LBA utilizable (primer LBA de la tabla de particiones secundaria − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | GUID del disco en formato mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | LBA inicial de una matriz de entradas de partición (siempre 2 en la copia primaria)                                                                                                     |
| 80 (0x50) | 4 bytes  | Cantidad de entradas de partición en la matriz                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Tamaño de una entrada de partición (normalmente 80h o 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 de la matriz de entradas de partición en little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reservado; debe ser cero en el resto del bloque (420 bytes para un tamaño de sector de 512 bytes, pero puede ser mayor con tamaños de sector más grandes)                                      |

**Entradas de partición (LBA 2–33)**

| Formato de entrada de partición GUID |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Desplazamiento                      | Longitud   | Contenido                                                                                                      |
| 0 (0x00)                    | 16 bytes | [GUID de tipo de partición](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | GUID único de la partición (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | Primer LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Último LBA (inclusive, normalmente impar)                                                                             |
| 48 (0x30)                   | 8 bytes  | Indicadores de atributos (p. ej., el bit 60 indica solo lectura)                                                               |
| 56 (0x38)                   | 72 bytes | Nombre de la partición (36 unidades de código [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                               |

**Tipos de particiones**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Nombre de la partición (36 unidades de código UTF-16LE)](<../../../images/image (83).png>)

Encontrarás más tipos de partición en [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspección

Después de montar la imagen forense con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), puedes inspeccionar el primer sector con la herramienta de Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** En la siguiente imagen se detectó e interpretó un **MBR** en el **sector 0**:

![GPT (GUID Partition Table) - Inspección: Después de montar la imagen forense con ArsenalImageMounter , puedes inspeccionar el primer sector con la herramienta de Windows Active Disk Editor . En la...](<../../../images/image (354).png>)

Para GPT, busca la firma _EFI PART_ en el encabezado primario de **LBA 1**; LBA 0 sigue conteniendo el MBR protector.<sup>[[4]](#references)</sup>

### Cómo encontrar datos fuera de las particiones enumeradas

Una entrada de partición eliminada o un espacio deliberadamente sin usar pueden dejar un sistema de archivos fuera del mapa de particiones actual. En una **copia de trabajo raw verificada**, enumera los rangos no asignados y luego prueba un LBA inicial candidato como sistema de archivos. `mmls` y `fsstat` usan **desplazamientos de sector**; proporciona a ambos el tamaño real del sector lógico. No confundas los sectores de metadatos GPT con un volumen oculto.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Si `fsstat` no puede identificar un sistema de archivos al inicio del espacio vacío, usa **Analyse → Quick Search** de TestDisk y, si es necesario, **Deeper Search**. Pulsa `P` sobre una opción candidata para inspeccionar los archivos; no selecciones **Write** en la evidencia. En imágenes GPT, `sgdisk --verify disk.img` comprueba los CRC y la concordancia entre las tablas principal y de respaldo, pero un encabezado de respaldo puede estar desactualizado después de reparticionar. Por eso, corrobora los límites candidatos con las estructuras del sistema de archivos antes de la recuperación.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Sistemas de archivos

### Lista de sistemas de archivos de Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

El sistema de archivos **FAT (File Allocation Table)** está diseñado en torno a su componente principal, la tabla de asignación de archivos, situada al inicio del volumen. Un volumen suele tener **dos copias de FAT**, aunque la BPB permite una. FAT12/16 ubican el directorio raíz en una región fija; FAT32 almacena el directorio raíz en el área de datos, en el clúster indicado por `BPB_RootClus`.<sup>[[7]](#references)</sup>

La unidad de asignación es un **clúster**: `BPB_BytsPerSec × BPB_SecPerClus`, que no necesariamente equivale a 512 bytes. El tipo de FAT se determina por la cantidad de clústeres de datos, no por una cadena de versión en el sector de arranque. Los límites de cantidad de clústeres son:<sup>[[7]](#references)</sup>

- **FAT12**: menos de 4.085 clústeres de datos.
- **FAT16**: de 4.085 a 65.524 clústeres de datos.
- **FAT32**: al menos 65.525 clústeres de datos; solo se usan 28 bits de cada entrada FAT de 32 bits para el número de clúster.

El campo de tamaño de archivo de 32 bits limita los archivos normales a **2³²−1 bytes** (apenas menos de 4 GiB).<sup>[[7]](#references)</sup>

Los componentes clave del directorio raíz, especialmente en FAT12 y FAT16, incluyen:

- **Nombre de archivo/carpeta** (hasta 8 caracteres)
- **Atributos**
- **Fechas de creación, modificación y último acceso**
- **Dirección de la tabla FAT** (indica el clúster inicial del archivo)
- **Tamaño del archivo**

### EXT

**Ext2** es el sistema de archivos más común para particiones **sin journaling** (**particiones que no cambian mucho**), como la partición de arranque. **Ext3/4** usan **journaling** y suelen utilizarse para las **demás particiones**.

## **Metadatos**

Algunos archivos contienen metadatos. Esta información describe el contenido del archivo y, en ocasiones, puede interesarle a un analista, ya que, según el tipo de archivo, puede incluir datos como:

- Título
- Versión de MS Office utilizada
- Autor
- Fechas de creación y última modificación
- Modelo de la cámara
- Coordenadas GPS
- Información de la imagen

Puedes usar herramientas como [**exiftool**](https://exiftool.org) y [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obtener los metadatos de un archivo.

## **Recuperación de archivos eliminados**

### Archivos eliminados registrados

Como se vio antes, hay varios lugares donde el archivo todavía se conserva después de haber sido «eliminado». Esto se debe a que, por lo general, al eliminar un archivo de un sistema de archivos solo se marca como eliminado, pero no se tocan los datos. Por lo tanto, es posible inspeccionar los registros de los archivos (como la MFT) y encontrar los archivos eliminados.<sup>[[2]](#references)</sup>

Además, el sistema operativo suele guardar mucha información sobre los cambios del sistema de archivos y las copias de seguridad, así que es posible intentar usarla para recuperar el archivo o tanta información como sea posible.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** es una técnica que intenta **encontrar archivos en el conjunto de datos**. Hay tres formas principales en que funcionan estas herramientas: **según los encabezados y pies de archivo**, según las **estructuras** de los tipos de archivo y según el **contenido** mismo.

El file carving simple basado en encabezados y pies presupone que los bloques son contiguos y puede devolver solo un fragmento si un archivo está dividido. Esto no es un límite absoluto: PhotoRec tiene una opción **Paranoid → bruteforce**, que exige mucho a la CPU, para algunos JPEG fragmentados, mientras que la reensambladura de fragmentos adaptada al formato puede recuperar otros tipos compatibles. Consulta [file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) para ver un flujo de trabajo actual de reensambladura de fragmentos.<sup>[[8]](#references)</sup>

Hay varias herramientas que puedes usar para file carving, indicando los tipos de archivo que quieres buscar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Data Stream Carving**

Data Stream Carving es similar a File Carving, pero **en lugar de buscar archivos completos, busca fragmentos de información interesantes**.\
Por ejemplo, en lugar de buscar un archivo completo que contenga URL registradas, esta técnica buscará URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Eliminación segura

Obviamente, hay formas de **eliminar «de forma segura» archivos y parte de los registros relacionados con ellos**. Por ejemplo, es posible **sobrescribir el contenido** de un archivo varias veces con datos basura y luego **eliminar** los **registros** del archivo en **$MFT** y **$LOGFILE**, además de **eliminar las copias de Volume Shadow**.<sup>[[3]](#references)</sup>\
Quizá notes que, incluso después de realizar esa acción, puede haber **otros lugares donde aún quede registrado que el archivo existió**. Y es cierto: encontrar esos rastros forma parte del trabajo de un profesional de análisis forense.



## References

- [1] [Tabla de particiones GUID - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Cómo analizar las entradas $I30 (directorio) de NTFS para encontrar evidencia de archivos eliminados](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Servicio Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [Especificación UEFI: diseño de disco GPT](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Manual de mmls de The Sleuth Kit](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Manual de fsstat de The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Especificación FAT de Microsoft](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Opciones de recuperación de PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Recuperación de particiones eliminadas con TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Manual de sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Manual de mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
