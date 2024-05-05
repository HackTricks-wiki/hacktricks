# Particiones/Sistemas de Archivos/Carving

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Particiones

Un disco duro o un **disco SSD puede contener diferentes particiones** con el objetivo de separar físicamente los datos.\
La unidad **mínima** de un disco es el **sector** (normalmente compuesto por 512B). Por lo tanto, el tamaño de cada partición debe ser múltiplo de ese tamaño.

### MBR (Registro de Arranque Maestro)

Se encuentra en el **primer sector del disco después de los 446B del código de arranque**. Este sector es esencial para indicar a la PC qué y desde dónde se debe montar una partición.\
Permite hasta **4 particiones** (como máximo **solo 1** puede ser activa/**de arranque**). Sin embargo, si necesitas más particiones puedes usar **particiones extendidas**. El **último byte** de este primer sector es la firma del registro de arranque **0x55AA**. Solo una partición puede estar marcada como activa.\
MBR permite **máximo 2.2TB**.

![](<../../../.gitbook/assets/image (350).png>)

![](<../../../.gitbook/assets/image (304).png>)

Desde los **bytes 440 al 443** del MBR puedes encontrar la **Firma del Disco de Windows** (si se usa Windows). La letra de unidad lógica del disco duro depende de la Firma del Disco de Windows. Cambiar esta firma podría evitar que Windows se inicie (herramienta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (310).png>)

**Formato**

| Offset      | Longitud   | Elemento            |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de arranque  |
| 446 (0x1BE) | 16 (0x10)  | Primera Partición   |
| 462 (0x1CE) | 16 (0x10)  | Segunda Partición   |
| 478 (0x1DE) | 16 (0x10)  | Tercera Partición   |
| 494 (0x1EE) | 16 (0x10)  | Cuarta Partición    |
| 510 (0x1FE) | 2 (0x2)    | Firma 0x55 0xAA      |

**Formato del Registro de Partición**

| Offset    | Longitud | Elemento                                                  |
| --------- | -------- | --------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Bandera activa (0x80 = de arranque)                       |
| 1 (0x01)  | 1 (0x01) | Cabeza de inicio                                         |
| 2 (0x02)  | 1 (0x01) | Sector de inicio (bits 0-5); bits superiores del cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01) | Bits más bajos del cilindro de inicio                     |
| 4 (0x04)  | 1 (0x01) | Código de tipo de partición (0x83 = Linux)                |
| 5 (0x05)  | 1 (0x01) | Cabeza de fin                                            |
| 6 (0x06)  | 1 (0x01) | Sector de fin (bits 0-5); bits superiores del cilindro (6- 7) |
| 7 (0x07)  | 1 (0x01) | Bits más bajos del cilindro de fin                        |
| 8 (0x08)  | 4 (0x04) | Sectores previos a la partición (poco endian)             |
| 12 (0x0C) | 4 (0x04) | Sectores en la partición                                  |

Para montar un MBR en Linux primero necesitas obtener el desplazamiento de inicio (puedes usar `fdisk` y el comando `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Y luego usar el siguiente código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Dirección de bloque lógico)**

**La dirección de bloque lógico** (**LBA**) es un esquema común utilizado para **especificar la ubicación de bloques** de datos almacenados en dispositivos de almacenamiento de computadoras, generalmente sistemas de almacenamiento secundario como discos duros. LBA es un esquema de direccionamiento lineal particularmente simple; **los bloques se localizan mediante un índice entero**, siendo el primer bloque LBA 0, el segundo LBA 1, y así sucesivamente.

### GPT (Tabla de particiones GUID)

La Tabla de Particiones GUID, conocida como GPT, es preferida por sus capacidades mejoradas en comparación con MBR (Registro de arranque principal). Distintiva por su **identificador único global** para particiones, GPT se destaca de varias maneras:

* **Ubicación y tamaño**: Tanto GPT como MBR comienzan en el **sector 0**. Sin embargo, GPT opera en **64 bits**, a diferencia de los 32 bits de MBR.
* **Límites de partición**: GPT admite hasta **128 particiones** en sistemas Windows y puede alojar hasta **9.4ZB** de datos.
* **Nombres de particiones**: Ofrece la capacidad de nombrar particiones con hasta 36 caracteres Unicode.

**Resiliencia y recuperación de datos**:

* **Redundancia**: A diferencia de MBR, GPT no limita la partición y los datos de arranque a un solo lugar. Replica estos datos en todo el disco, mejorando la integridad y resiliencia de los datos.
* **Verificación cíclica de redundancia (CRC)**: GPT emplea CRC para garantizar la integridad de los datos. Monitorea activamente la corrupción de datos y, cuando se detecta, GPT intenta recuperar los datos corruptos desde otra ubicación en el disco.

**MBR protector (LBA0)**:

* GPT mantiene la compatibilidad hacia atrás a través de un MBR protector. Esta característica reside en el espacio MBR heredado pero está diseñada para evitar que utilidades MBR más antiguas sobrescriban por error discos GPT, protegiendo así la integridad de los datos en discos formateados con GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (1062).png>)

**MBR híbrido (LBA 0 + GPT)**

[Desde Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

En sistemas operativos que admiten **arranque basado en GPT a través de servicios BIOS** en lugar de EFI, el primer sector también puede usarse para almacenar la primera etapa del código del **cargador de arranque**, pero **modificado** para reconocer **particiones GPT**. El cargador de arranque en el MBR no debe asumir un tamaño de sector de 512 bytes.

**Encabezado de la tabla de particiones (LBA 1)**

[Desde Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

El encabezado de la tabla de particiones define los bloques utilizables en el disco. También define el número y tamaño de las entradas de partición que conforman la tabla de particiones (desplazamientos 80 y 84 en la tabla).

| Desplazamiento | Longitud | Contenido                                                                                                                                                                        |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)       | 8 bytes  | Firma ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h o 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)en máquinas little-endian) |
| 8 (0x08)       | 4 bytes  | Revisión 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                     |
| 12 (0x0C)      | 4 bytes  | Tamaño del encabezado en little-endian (en bytes, generalmente 5Ch 00h 00h 00h o 92 bytes)                                                                                       |
| 16 (0x10)      | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) del encabezado (desplazamiento +0 hasta tamaño del encabezado) en little-endian, con este campo en cero durante el cálculo         |
| 20 (0x14)      | 4 bytes  | Reservado; debe ser cero                                                                                                                                                         |
| 24 (0x18)      | 8 bytes  | LBA actual (ubicación de esta copia del encabezado)                                                                                                                              |
| 32 (0x20)      | 8 bytes  | LBA de respaldo (ubicación de la otra copia del encabezado)                                                                                                                      |
| 40 (0x28)      | 8 bytes  | Primer LBA utilizable para particiones (último LBA de la tabla de particiones primaria + 1)                                                                                       |
| 48 (0x30)      | 8 bytes  | Último LBA utilizable (primer LBA de la tabla de particiones secundaria − 1)                                                                                                     |
| 56 (0x38)      | 16 bytes | GUID del disco en endian mixto                                                                                                                                                   |
| 72 (0x48)      | 8 bytes  | LBA de inicio de una matriz de entradas de partición (siempre 2 en la copia primaria)                                                                                            |
| 80 (0x50)      | 4 bytes  | Número de entradas de partición en la matriz                                                                                                                                      |
| 84 (0x54)      | 4 bytes  | Tamaño de una sola entrada de partición (generalmente 80h o 128)                                                                                                                  |
| 88 (0x58)      | 4 bytes  | CRC32 de la matriz de entradas de partición en little-endian                                                                                                                      |
| 92 (0x5C)      | \*       | Reservado; deben ser ceros para el resto del bloque (420 bytes para un tamaño de sector de 512 bytes; pero puede ser más con tamaños de sector más grandes)                     |

**Entradas de particiones (LBA 2–33)**

| Formato de entrada de partición GUID |          |                                                                                                                   |
| ----------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Desplazamiento                      | Longitud | Contenido                                                                                                          |
| 0 (0x00)                            | 16 bytes | [GUID del tipo de partición](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (endian mixto) |
| 16 (0x10)                           | 16 bytes | GUID de partición único (endian mixto)                                                                             |
| 32 (0x20)                           | 8 bytes  | Primer LBA ([little-endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                           | 8 bytes  | Último LBA (inclusive, generalmente impar)                                                                         |
| 48 (0x30)                           | 8 bytes  | Banderas de atributo (por ejemplo, el bit 60 denota solo lectura)                                                   |
| 56 (0x38)                           | 72 bytes | Nombre de la partición (36 unidades de código UTF-16LE)                                                           |

**Tipos de particiones**

![](<../../../.gitbook/assets/image (83).png>)

Más tipos de particiones en [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspección

Después de montar la imagen forense con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), puedes inspeccionar el primer sector utilizando la herramienta de Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** En la siguiente imagen se detectó un **MBR** en el **sector 0** e interpretado:

![](<../../../.gitbook/assets/image (354).png>)

Si fuera una **tabla GPT en lugar de un MBR**, debería aparecer la firma _EFI PART_ en el **sector 1** (que en la imagen anterior está vacío).
## Sistemas de archivos

### Lista de sistemas de archivos de Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

El sistema de archivos **FAT (File Allocation Table)** está diseñado en torno a su componente central, la tabla de asignación de archivos, ubicada al inicio del volumen. Este sistema protege los datos manteniendo **dos copias** de la tabla, asegurando la integridad de los datos incluso si una se corrompe. La tabla, junto con la carpeta raíz, debe estar en una **ubicación fija**, crucial para el proceso de inicio del sistema.

La unidad básica de almacenamiento del sistema de archivos es un **clúster, generalmente de 512B**, que comprende varios sectores. FAT ha evolucionado a través de versiones:

* **FAT12**, que admite direcciones de clúster de 12 bits y maneja hasta 4078 clústeres (4084 con UNIX).
* **FAT16**, mejorando a direcciones de 16 bits, pudiendo alojar hasta 65,517 clústeres.
* **FAT32**, avanzando aún más con direcciones de 32 bits, permitiendo un impresionante número de 268,435,456 clústeres por volumen.

Una limitación significativa en todas las versiones de FAT es el **tamaño máximo de archivo de 4GB**, impuesto por el campo de 32 bits utilizado para el almacenamiento del tamaño del archivo.

Los componentes clave del directorio raíz, especialmente para FAT12 y FAT16, incluyen:

* **Nombre de archivo/carpeta** (hasta 8 caracteres)
* **Atributos**
* **Fechas de creación, modificación y último acceso**
* **Dirección de la tabla FAT** (indicando el clúster de inicio del archivo)
* **Tamaño del archivo**

### EXT

**Ext2** es el sistema de archivos más común para particiones **sin registro de diario** (particiones que no cambian mucho) como la partición de arranque. **Ext3/4** son **con registro de diario** y se utilizan generalmente para las **otras particiones**.

## **Metadatos**

Algunos archivos contienen metadatos. Esta información es sobre el contenido del archivo que a veces puede ser interesante para un analista, ya que dependiendo del tipo de archivo, podría contener información como:

* Título
* Versión de MS Office utilizada
* Autor
* Fechas de creación y última modificación
* Modelo de la cámara
* Coordenadas GPS
* Información de la imagen

Puedes utilizar herramientas como [**exiftool**](https://exiftool.org) y [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obtener los metadatos de un archivo.

## **Recuperación de archivos eliminados**

### Archivos eliminados registrados

Como se vio anteriormente, hay varios lugares donde el archivo aún se guarda después de ser "eliminado". Esto se debe a que generalmente la eliminación de un archivo de un sistema de archivos solo lo marca como eliminado pero los datos no se tocan. Entonces, es posible inspeccionar los registros de los archivos (como el MFT) y encontrar los archivos eliminados.

Además, el sistema operativo generalmente guarda mucha información sobre los cambios en el sistema de archivos y las copias de seguridad, por lo que es posible intentar usarlos para recuperar el archivo o la mayor cantidad de información posible.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Tallado de archivos**

El **tallado de archivos** es una técnica que intenta **encontrar archivos en el conjunto de datos**. Hay 3 formas principales en las que funcionan herramientas como esta: **Basado en encabezados y pies de página de tipos de archivo**, basado en **estructuras de tipos de archivo** y basado en el **contenido** en sí.

Ten en cuenta que esta técnica **no funciona para recuperar archivos fragmentados**. Si un archivo **no se almacena en sectores contiguos**, entonces esta técnica no podrá encontrarlo o al menos parte de él.

Hay varias herramientas que puedes utilizar para tallar archivos indicando los tipos de archivo que deseas buscar.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Tallado de **flujos de datos**

El Tallado de flujos de datos es similar al Tallado de archivos pero **en lugar de buscar archivos completos, busca fragmentos interesantes** de información.\
Por ejemplo, en lugar de buscar un archivo completo que contenga URL registradas, esta técnica buscará URLs.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Eliminación segura

Obviamente, existen formas de **eliminar archivos de manera "segura" y parte de los registros sobre ellos**. Por ejemplo, es posible **sobrescribir el contenido** de un archivo con datos basura varias veces, y luego **eliminar** los **registros** del **$MFT** y **$LOGFILE** sobre el archivo, y **eliminar las copias de seguridad de volumen**.\
Puedes notar que incluso realizando esa acción, podría haber **otras partes donde la existencia del archivo aún esté registrada**, y es cierto que parte del trabajo del profesional forense es encontrarlas.

## Referencias

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**
