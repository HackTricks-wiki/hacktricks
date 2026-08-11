# Particiones/Sistemas de archivos/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Particiones

Un disco duro o un **disco SSD puede contener diferentes particiones** con el objetivo de separar los datos físicamente.\
La unidad **mínima** de un disco es el **sector** (normalmente compuesto por 512B). Por lo tanto, el tamaño de cada partición debe ser múltiplo de ese tamaño.

### MBR (master Boot Record)

Se asigna en el **primer sector del disco después de los 446B del código de arranque**. Este sector es esencial para indicar al PC qué partición debe montarse y desde dónde.\
Permite hasta **4 particiones** (como máximo **solo 1** puede estar activa/**ser de arranque**). Sin embargo, si necesitas más particiones, puedes utilizar **particiones extendidas**. El **byte final** de este primer sector es la firma del boot record **0x55AA**. Solo una partición puede marcarse como activa.\
MBR permite **un máximo de 2.2TB**.

![Particiones - MBR (master Boot Record): MBR permite un máximo de 2.2TB](<../../../images/image (350).png>)

![Particiones - MBR (master Boot Record): MBR permite un máximo de 2.2TB](<../../../images/image (304).png>)

En los **bytes 440 a 443** del MBR puedes encontrar la **Windows Disk Signature** (si se utiliza Windows). La letra de la unidad lógica del disco duro depende de la Windows Disk Signature. Cambiar esta firma podría impedir que Windows arranque (herramienta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Particiones - MBR (master Boot Record): En los bytes 440 a 443 del MBR puedes encontrar la Windows Disk Signature (si se utiliza Windows). La letra de la unidad lógica del disco duro...](<../../../images/image (310).png>)

**Formato**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de arranque  |
| 446 (0x1BE) | 16 (0x10)  | Primera partición   |
| 462 (0x1CE) | 16 (0x10)  | Segunda partición   |
| 478 (0x1DE) | 16 (0x10)  | Tercera partición   |
| 494 (0x1EE) | 16 (0x10)  | Cuarta partición    |
| 510 (0x1FE) | 2 (0x2)    | Firma 0x55 0xAA     |

**Formato del registro de partición**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Indicador activo (0x80 = de arranque)                 |
| 1 (0x01)  | 1 (0x01) | Cabezal de inicio                                      |
| 2 (0x02)  | 1 (0x01) | Sector de inicio (bits 0-5); bits superiores del cilindro (6-7) |
| 3 (0x03)  | 1 (0x01) | 8 bits inferiores del cilindro de inicio              |
| 4 (0x04)  | 1 (0x01) | Código de tipo de partición (0x83 = Linux)            |
| 5 (0x05)  | 1 (0x01) | Cabezal final                                          |
| 6 (0x06)  | 1 (0x01) | Sector final (bits 0-5); bits superiores del cilindro (6-7) |
| 7 (0x07)  | 1 (0x01) | 8 bits inferiores del cilindro final                   |
| 8 (0x08)  | 4 (0x04) | Sectores que preceden a la partición (little endian)  |
| 12 (0x0C) | 4 (0x04) | Sectores de la partición                              |

Para montar un MBR en Linux, primero necesitas obtener el offset de inicio (puedes utilizar `fdisk` y el comando `p`).

![Particiones - MBR (master Boot Record): Para montar un MBR en Linux, primero necesitas obtener el offset de inicio (puedes utilizar fdisk y el comando p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Y luego utiliza el siguiente código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) es un esquema común utilizado para **especificar la ubicación de bloques** de datos almacenados en dispositivos de almacenamiento informático, generalmente sistemas de almacenamiento secundario como las unidades de disco duro. LBA es un esquema de direccionamiento lineal particularmente sencillo; **los bloques se ubican mediante un índice entero**, siendo el primer bloque LBA 0, el segundo LBA 1, y así sucesivamente.

### GPT (GUID Partition Table)

La GUID Partition Table, conocida como GPT, es preferida por sus capacidades mejoradas en comparación con MBR (Master Boot Record). Distintiva por su **identificador globalmente único** para las particiones, GPT destaca en varios aspectos:

- **Ubicación y tamaño**: Tanto GPT como MBR comienzan en el **sector 0**. Sin embargo, GPT opera con **64bits**, a diferencia de los 32bits de MBR.
- **Límites de las particiones**: GPT admite hasta **128 particiones** en sistemas Windows y permite gestionar hasta **9.4ZB** de datos.
- **Nombres de las particiones**: Permite asignar nombres a las particiones con hasta 36 caracteres Unicode.

**Resiliencia y recuperación de datos**:

- **Redundancia**: A diferencia de MBR, GPT no limita los datos de particionado y arranque a un único lugar. Replica estos datos en distintas ubicaciones del disco, mejorando la integridad y la resiliencia de los datos.
- **Cyclic Redundancy Check (CRC)**: GPT emplea CRC para garantizar la integridad de los datos. Supervisa activamente la corrupción de datos y, cuando la detecta, GPT intenta recuperar los datos corruptos desde otra ubicación del disco.

**Protective MBR (LBA0)**:

- GPT mantiene la compatibilidad con versiones anteriores mediante un protective MBR. Esta característica se encuentra en el espacio del MBR heredado, pero está diseñada para impedir que las utilidades antiguas basadas en MBR sobrescriban por error los discos GPT, protegiendo así la integridad de los datos en los discos formateados con GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[De Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

En los sistemas operativos que admiten el arranque **basado en GPT mediante servicios de BIOS**, en lugar de EFI, el primer sector también puede seguir utilizándose para almacenar el código de la primera fase del **bootloader**, pero **modificado** para reconocer las **particiones** **GPT**. El bootloader del MBR no debe asumir un tamaño de sector de 512 bytes.

**Encabezado de la tabla de particiones (LBA 1)**

[De Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

El encabezado de la tabla de particiones define los bloques utilizables del disco. También define el número y el tamaño de las entradas de partición que componen la tabla de particiones (offsets 80 y 84 de la tabla).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                             |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                      |

**Entradas de partición (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Tipos de particiones**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Más tipos de particiones en [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspección

Después de montar la imagen forense con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), puedes inspeccionar el primer sector utilizando la herramienta de Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** En la siguiente imagen se detectó un **MBR** en el **sector 0** y se interpretó:

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

Si fuera una **tabla GPT en lugar de un MBR**, debería aparecer la firma _EFI PART_ en el **sector 1** (que en la imagen anterior está vacío).

## Sistemas de archivos

### Lista de sistemas de archivos de Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

El sistema de archivos **FAT (File Allocation Table)** está diseñado en torno a su componente principal, la tabla de asignación de archivos, ubicada al principio del volumen. Este sistema protege los datos manteniendo **dos copias** de la tabla, garantizando la integridad de los datos incluso si una de ellas se corrompe. La tabla, junto con la carpeta raíz, debe encontrarse en una **ubicación fija**, algo crucial para el proceso de inicio del sistema.

La unidad básica de almacenamiento del sistema de archivos es un **cluster, normalmente de 512B**, compuesto por varios sectores. FAT ha evolucionado a través de varias versiones:

- **FAT12**, compatible con direcciones de cluster de 12 bits y capaz de gestionar hasta 4078 clusters (4084 con UNIX).
- **FAT16**, que amplía las direcciones a 16 bits, permitiendo gestionar hasta 65,517 clusters.
- **FAT32**, que avanza hasta direcciones de 32 bits y permite unos impresionantes 268,435,456 clusters por volumen.

Una limitación importante de todas las versiones de FAT es el **tamaño máximo de archivo de 4GB**, impuesto por el campo de 32 bits utilizado para almacenar el tamaño del archivo.

Entre los componentes principales del directorio raíz, especialmente en FAT12 y FAT16, se incluyen:

- **Nombre de archivo/carpeta** (hasta 8 caracteres)
- **Atributos**
- **Fechas de creación, modificación y último acceso**
- **Dirección de la tabla FAT** (que indica el cluster inicial del archivo)
- **Tamaño del archivo**

### EXT

**Ext2** es el sistema de archivos más común para particiones **sin journaling** (**particiones que no cambian mucho**), como la partición de arranque. **Ext3/4** utilizan **journaling** y normalmente se emplean para el **resto de las particiones**.

## **Metadatos**

Algunos archivos contienen metadatos. Esta información describe el contenido del archivo y, en ocasiones, puede resultar interesante para un analista, ya que, dependiendo del tipo de archivo, puede incluir información como:

- Título
- Versión de MS Office utilizada
- Autor
- Fechas de creación y última modificación
- Modelo de la cámara
- Coordenadas GPS
- Información de la imagen

Puedes utilizar herramientas como [**exiftool**](https://exiftool.org) y [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obtener los metadatos de un archivo.

## **Recuperación de archivos eliminados**

### Archivos eliminados registrados

Como se ha visto anteriormente, existen varios lugares donde el archivo todavía se conserva después de haber sido "eliminado". Esto se debe a que normalmente la eliminación de un archivo de un sistema de archivos solo lo marca como eliminado, pero los datos no se modifican. Por tanto, es posible inspeccionar los registros de los archivos (como la MFT) y encontrar los archivos eliminados.<sup>[[2]](#references)</sup>

Además, el sistema operativo normalmente guarda mucha información sobre los cambios y las copias de seguridad del sistema de archivos, por lo que es posible intentar utilizarlos para recuperar el archivo o la mayor cantidad de información posible.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** es una técnica que intenta **encontrar archivos en el conjunto de datos**. Existen 3 formas principales en las que funcionan herramientas de este tipo: **basándose en las cabeceras y los pies de los tipos de archivo**, basándose en las **estructuras** de los tipos de archivo y basándose en el **contenido** mismo.

Ten en cuenta que esta técnica **no funciona para recuperar archivos fragmentados**. Si un archivo **no está almacenado en sectores contiguos**, esta técnica no podrá encontrarlo, o al menos no podrá encontrar una parte de él.

Existen varias herramientas que puedes utilizar para File Carving, indicando los tipos de archivo que deseas buscar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving es similar a File Carving, pero **en lugar de buscar archivos completos, busca fragmentos de información interesantes**.\
Por ejemplo, en lugar de buscar un archivo completo que contenga URLs registradas, esta técnica buscará URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Obviamente, existen formas de **eliminar archivos y partes de los logs relacionados con ellos de forma "segura"**. Por ejemplo, es posible **sobrescribir el contenido** de un archivo varias veces con datos basura y, después, **eliminar** los **logs** del **$MFT** y **$LOGFILE** relacionados con el archivo, además de **eliminar las Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Es posible que observes que, incluso realizando esa acción, puede haber **otras partes donde la existencia del archivo siga registrada**, y es cierto; encontrar esas partes forma parte del trabajo de un profesional de forensics.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Cómo analizar las entradas NTFS $I30 (directorio) en busca de evidencias de archivos eliminados](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Servicio Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
