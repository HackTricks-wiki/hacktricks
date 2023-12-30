# Particiones/Sistemas de Archivos/Carving

## Particiones/Sistemas de Archivos/Carving

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Particiones

Un disco duro o un **SSD puede contener diferentes particiones** con el objetivo de separar datos físicamente.\
La **unidad mínima** de un disco es el **sector** (normalmente compuesto de 512B). Por lo tanto, el tamaño de cada partición debe ser múltiplo de ese tamaño.

### MBR (Master Boot Record)

Se encuentra en el **primer sector del disco después de los 446B del código de arranque**. Este sector es esencial para indicar al PC qué y desde dónde debe montarse una partición.\
Permite hasta **4 particiones** (como máximo **solo 1** puede ser activa/**arrancable**). Sin embargo, si necesitas más particiones puedes usar **particiones extendidas**. El **byte final** de este primer sector es la firma del registro de arranque **0x55AA**. Solo una partición puede ser marcada como activa.\
MBR permite un **máximo de 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Desde los **bytes 440 al 443** del MBR puedes encontrar la **Firma de Disco de Windows** (si se usa Windows). La letra de unidad lógica del disco duro depende de la Firma de Disco de Windows. Cambiar esta firma podría impedir que Windows arranque (herramienta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Formato**

| Desplazamiento | Longitud  | Elemento             |
| -------------- | --------- | -------------------- |
| 0 (0x00)       | 446(0x1BE)| Código de arranque   |
| 446 (0x1BE)    | 16 (0x10) | Primera Partición    |
| 462 (0x1CE)    | 16 (0x10) | Segunda Partición    |
| 478 (0x1DE)    | 16 (0x10) | Tercera Partición    |
| 494 (0x1EE)    | 16 (0x10) | Cuarta Partición     |
| 510 (0x1FE)    | 2 (0x2)   | Firma 0x55 0xAA      |

**Formato de Registro de Partición**

| Desplazamiento | Longitud  | Elemento                                               |
| -------------- | --------- | ------------------------------------------------------ |
| 0 (0x00)       | 1 (0x01)  | Bandera activa (0x80 = arrancable)                     |
| 1 (0x01)       | 1 (0x01)  | Cabeza inicial                                         |
| 2 (0x02)       | 1 (0x01)  | Sector inicial (bits 0-5); bits altos del cilindro (6-7)|
| 3 (0x03)       | 1 (0x01)  | Cilindro inicial 8 bits más bajos                      |
| 4 (0x04)       | 1 (0x01)  | Código de tipo de partición (0x83 = Linux)             |
| 5 (0x05)       | 1 (0x01)  | Cabeza final                                           |
| 6 (0x06)       | 1 (0x01)  | Sector final (bits 0-5); bits altos del cilindro (6-7) |
| 7 (0x07)       | 1 (0x01)  | Cilindro final 8 bits más bajos                        |
| 8 (0x08)       | 4 (0x04)  | Sectores que preceden a la partición (little endian)   |
| 12 (0x0C)      | 4 (0x04)  | Sectores en la partición                               |

Para montar un MBR en Linux primero necesitas obtener el desplazamiento inicial (puedes usar `fdisk` y el comando `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

Y luego usar el siguiente código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**La dirección de bloque lógico** (**LBA**) es un esquema común utilizado para **especificar la ubicación de bloques** de datos almacenados en dispositivos de almacenamiento de computadoras, generalmente sistemas de almacenamiento secundario como discos duros. LBA es un esquema de direccionamiento lineal particularmente simple; **los bloques se ubican mediante un índice entero**, siendo el primer bloque LBA 0, el segundo LBA 1, y así sucesivamente.

### GPT (GUID Partition Table)

Se llama Tabla de Particiones GUID porque cada partición en su unidad tiene un **identificador único a nivel mundial**.

Al igual que MBR, comienza en el **sector 0**. El MBR ocupa 32 bits mientras que **GPT** usa **64 bits**.\
GPT **permite hasta 128 particiones** en Windows y hasta **9.4ZB**.\
Además, las particiones pueden tener un nombre Unicode de 36 caracteres.

En un disco MBR, los datos de particionamiento y arranque se almacenan en un solo lugar. Si estos datos se sobrescriben o se corrompen, tienes problemas. En contraste, **GPT almacena múltiples copias de estos datos a lo largo del disco**, por lo que es mucho más robusto y puede recuperarse si los datos están dañados.

GPT también almacena valores de **verificación de redundancia cíclica (CRC)** para verificar que sus datos estén intactos. Si los datos están dañados, GPT puede notar el problema e **intentar recuperar los datos dañados** de otra ubicación en el disco.

**MBR protector (LBA0)**

Para compatibilidad limitada hacia atrás, el espacio del MBR legado aún se reserva en la especificación de GPT, pero ahora se utiliza de una **manera que evita que las utilidades de disco basadas en MBR reconozcan erróneamente y posiblemente sobrescriban discos GPT**. Esto se conoce como un MBR protector.

![](<../../../.gitbook/assets/image (491).png>)

**MBR híbrido (LBA 0 + GPT)**

En sistemas operativos que admiten el arranque **basado en GPT a través de servicios BIOS** en lugar de EFI, el primer sector también puede usarse para almacenar la primera etapa del código del **bootloader**, pero **modificado** para reconocer **particiones GPT**. El bootloader en el MBR no debe asumir un tamaño de sector de 512 bytes.

**Encabezado de la tabla de particiones (LBA 1)**

El encabezado de la tabla de particiones define los bloques utilizables en el disco. También define el número y tamaño de las entradas de partición que componen la tabla de particiones (desplazamientos 80 y 84 en la tabla).

| Desplazamiento | Longitud | Contenidos                                                                                                                                                                        |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)       | 8 bytes  | Firma ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h o 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8) en máquinas little-endian) |
| 8 (0x08)       | 4 bytes  | Revisión 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                     |
| 12 (0x0C)      | 4 bytes  | Tamaño del encabezado en little endian (en bytes, usualmente 5Ch 00h 00h 00h o 92 bytes)                                                                                                    |
| 16 (0x10)      | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) del encabezado (desplazamiento +0 hasta el tamaño del encabezado) en little endian, con este campo puesto a cero durante el cálculo                                |
| 20 (0x14)      | 4 bytes  | Reservado; debe ser cero                                                                                                                                                          |
| 24 (0x18)      | 8 bytes  | LBA actual (ubicación de esta copia del encabezado)                                                                                                                                      |
| 32 (0x20)      | 8 bytes  | LBA de respaldo (ubicación de la otra copia del encabezado)                                                                                                                                  |
| 40 (0x28)      | 8 bytes  | Primer LBA utilizable para particiones (último LBA de la tabla de particiones primaria + 1)                                                                                                          |
| 48 (0x30)      | 8 bytes  | Último LBA utilizable (primer LBA de la tabla de particiones secundaria − 1)                                                                                                                       |
| 56 (0x38)      | 16 bytes | GUID del disco en endian mixto                                                                                                                                                       |
| 72 (0x48)      | 8 bytes  | LBA de inicio de un arreglo de entradas de partición (siempre 2 en la copia primaria)                                                                                                        |
| 80 (0x50)      | 4 bytes  | Número de entradas de partición en el arreglo                                                                                                                                            |
| 84 (0x54)      | 4 bytes  | Tamaño de una sola entrada de partición (usualmente 80h o 128)                                                                                                                           |
| 88 (0x58)      | 4 bytes  | CRC32 del arreglo de entradas de partición en little endian                                                                                                                               |
| 92 (0x5C)      | \*       | Reservado; debe ser ceros para el resto del bloque (420 bytes para un tamaño de sector de 512 bytes; pero puede ser más con tamaños de sector mayores)                                         |

**Entradas de partición (LBA 2–33)**

| Formato de entrada de partición GUID |          |                                                                                                                   |
| ------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Desplazamiento                       | Longitud | Contenidos                                                                                                          |
| 0 (0x00)                             | 16 bytes | [GUID del tipo de partición](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (endian mixto) |
| 16 (0x10)                            | 16 bytes | GUID único de la partición (endian mixto)                                                                              |
| 32 (0x20)                            | 8 bytes  | Primer LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                            | 8 bytes  | Último LBA (inclusivo, usualmente impar)                                                                                 |
| 48 (0x30)                            | 8 bytes  | Banderas de atributos (por ejemplo, el bit 60 denota solo lectura)                                                                   |
| 56 (0x38)                            | 72 bytes | Nombre de la partición (36 unidades de código [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                                   |

**Tipos de Particiones**

![](<../../../.gitbook/assets/image (492).png>)

Más tipos de particiones en [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspección

Después de montar la imagen forense con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), puedes inspeccionar el primer sector utilizando la herramienta de Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** En la siguiente imagen se detectó un **MBR** en el **sector 0** e interpretado:

![](<../../../.gitbook/assets/image (494).png>)

Si fuera una **tabla GPT en lugar de un MBR** debería aparecer la firma _EFI PART_ en el **sector 1** (que en la imagen anterior está vacío).

## Sistemas de Archivos

### Lista de sistemas de archivos de Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

El sistema de archivos **FAT (File Allocation Table)** se llama así por su método de organización, la tabla de asignación de archivos, que se encuentra al principio del volumen. Para proteger el volumen, se mantienen **dos copias** de la tabla, en caso de que una se dañe. Además, las tablas de asignación de archivos y la carpeta raíz deben almacenarse en una **ubicación fija** para que los archivos necesarios para iniciar el sistema puedan ser localizados correctamente.

![](<../../../.gitbook/assets/image (495).png>)

La unidad mínima de espacio utilizada por este sistema de archivos es un **cluster, típicamente 512B** (que está compuesto por varios sectores).

El anterior **FAT12** tenía direcciones de **cluster a valores de 12 bits** con hasta **4078** **clusters**; permitía hasta 4084 clusters con UNIX. El más eficiente **FAT16** aumentó a direcciones de cluster de **16 bits** permitiendo hasta **65,517 clusters** por volumen. FAT32 usa direcciones de cluster de 32 bits permitiendo hasta **268,435,456 clusters** por volumen

El **tamaño máximo de archivo permitido por FAT es 4GB** (menos un byte) porque el sistema de archivos utiliza un campo de 32 bits para almacenar el tamaño del archivo en bytes, y 2^32 bytes = 4 GiB. Esto ocurre para FAT12, FAT16 y FAT32.

El **directorio raíz** ocupa una **posición específica** tanto para FAT12 como para FAT16 (en FAT32 ocupa una posición como cualquier otra carpeta). Cada entrada de archivo/carpeta contiene esta información:

* Nombre del archivo/carpeta (máximo 8 caracteres)
* Atributos
* Fecha de creación
* Fecha de modificación
* Fecha de último acceso
* Dirección de la tabla FAT donde comienza el primer cluster del archivo
* Tamaño

Cuando un archivo se "elimina" usando un sistema de archivos FAT, la entrada del directorio permanece casi **sin cambios** excepto por el **primer carácter del nombre del archivo** (modificado a 0xE5), preservando la mayor parte del nombre del archivo "eliminado", junto con su sello de tiempo, longitud del archivo y — lo más importante — su ubicación física en el disco. La lista de clusters de disco ocupados por el archivo, sin embargo, se borrará de la Tabla de Asignación de Archivos, marcando esos sectores disponibles para su uso por otros archivos creados o modificados posteriormente. En el caso de FAT32, adicionalmente se borra un campo responsable de los 16 bits superiores del valor del cluster de inicio del archivo.

### **NTFS**

{% content-ref url="ntfs.md" %}
[ntfs.md](ntfs.md)
{% endcontent-ref %}

### EXT

**Ext2** es el sistema de archivos más común para particiones **sin journaling** (**particiones que no cambian mucho**) como la partición de arranque. **Ext3/4** son **con journaling** y se utilizan generalmente para las **demás particiones**.

{% content-ref url="ext.md" %}
[ext.md](ext.md)
{% endcontent-ref %}

## **Metadatos**

Algunos archivos contienen metadatos. Esta información es sobre el contenido del archivo que a veces puede ser interesante para un analista ya que, dependiendo del tipo de archivo, podría tener información como:

* Título
* Versión de MS Office utilizada
* Autor
* Fechas de creación y última modificación
* Modelo de la cámara
* Coordenadas GPS
* Información de la imagen

Puedes usar herramientas como [**exiftool**](https://exiftool.org) y [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obtener los metadatos de un archivo.

## **Recuperación de Archivos Eliminados**

### Archivos Eliminados Registrados

Como se vio anteriormente, hay varios lugares donde el archivo aún se guarda después de que fue "eliminado". Esto se debe a que generalmente la eliminación de un archivo de un sistema de archivos solo lo marca como eliminado, pero los datos no se tocan. Entonces, es posible inspeccionar los registros de los archivos (como el MFT) y encontrar los archivos eliminados.

Además, el sistema operativo generalmente guarda mucha información sobre cambios en el sistema de archivos y copias de seguridad, por lo que es posible intentar usarlos para recuperar el archivo o tanta información como sea posible.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **File Carving**

**File carving** es una técnica que intenta **encontrar archivos en el volumen de datos**. Hay 3 formas principales en que herramientas como esta funcionan: **Basadas en encabezados y pies de página de tipos de archivos**, basadas en **estructuras de tipos de archivos** y basadas en el **contenido** en sí.

Ten en cuenta que esta técnica **no funciona para recuperar archivos fragmentados**. Si un archivo **no se almacena en sectores contiguos**, entonces esta técnica no podrá encontrarlo o al menos parte de él.

Hay varias herramientas que puedes usar para File Carving indicando los tipos de archivos que deseas buscar.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Carving de Flujo de Datos

El Carving de Flujo de Datos es similar al File Carving pero **en lugar de buscar archivos completos, busca fragmentos de información interesantes**.\
Por ejemplo, en lugar de buscar un archivo completo que contenga URLs registradas, esta técnica buscará URLs.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Eliminación Segura

Obviamente, hay formas de **eliminar "de forma segura" archivos y parte de los registros sobre ellos**. Por ejemplo, es posible **sobrescribir el contenido** de un archivo con datos basura varias veces, y luego **eliminar los registros** del **$MFT** y **$LOGFILE** sobre el archivo, y **eliminar las Copias de Sombra del Volumen**.\
Puedes notar que incluso realizando esa acción todavía puede haber **otras partes donde la existencia del archivo aún está registrada**, y eso es cierto y parte del trabajo del profesional forense es encontrarlas.

## Referencias

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
