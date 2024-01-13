<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Ext - Sistema de Archivos Extendido

**Ext2** es el sistema de archivos más común para particiones **sin journaling** (**particiones que no cambian mucho**) como la partición de arranque. **Ext3/4** son **con journaling** y se utilizan normalmente para el **resto de las particiones**.

Todos los grupos de bloques en el sistema de archivos tienen el mismo tamaño y se almacenan secuencialmente. Esto permite al kernel derivar fácilmente la ubicación de un grupo de bloques en un disco a partir de su índice entero.

Cada grupo de bloques contiene la siguiente información:

* Una copia del superbloque del sistema de archivos
* Una copia de los descriptores de grupo de bloques
* Un mapa de bits de bloques de datos que se utiliza para identificar los bloques libres dentro del grupo
* Un mapa de bits de inodos, que se utiliza para identificar los inodos libres dentro del grupo
* tabla de inodos: consiste en una serie de bloques consecutivos, cada uno de los cuales contiene un número predefinido de inodos de Ext2. Todos los inodos tienen el mismo tamaño: 128 bytes. Un bloque de 1,024 bytes contiene 8 inodos, mientras que un bloque de 4,096 bytes contiene 32 inodos. Cabe destacar que en Ext2, no es necesario almacenar en disco un mapeo entre un número de inodo y el número de bloque correspondiente porque este último valor se puede derivar del número de grupo de bloques y la posición relativa dentro de la tabla de inodos. Por ejemplo, supongamos que cada grupo de bloques contiene 4,096 inodos y queremos saber la dirección en el disco del inodo 13,021. En este caso, el inodo pertenece al tercer grupo de bloques y su dirección de disco se almacena en la entrada 733 de la tabla de inodos correspondiente. Como puedes ver, el número de inodo es simplemente una clave utilizada por las rutinas de Ext2 para recuperar rápidamente el descriptor de inodo adecuado en el disco
* bloques de datos, que contienen archivos. Cualquier bloque que no contenga información significativa se considera libre.

![](<../../../.gitbook/assets/image (406).png>)

## Características Opcionales de Ext

**Las características afectan dónde** se encuentra la información, **cómo** se almacena la información en los inodos y algunas de ellas pueden proporcionar **metadatos adicionales** para el análisis, por lo tanto, las características son importantes en Ext.

Ext tiene características opcionales que tu sistema operativo puede o no soportar, hay 3 posibilidades:

* Compatible
* Incompatible
* Solo Lectura Compatible: Se puede montar pero no para escribir

Si hay características **incompatibles** no podrás montar el sistema de archivos ya que el sistema operativo no sabrá cómo acceder a los datos.

{% hint style="info" %}
Un atacante sospechoso podría tener extensiones no estándar
{% endhint %}

**Cualquier utilidad** que lea el **superbloque** podrá indicar las **características** de un **sistema de archivos Ext**, pero también podrías usar `file -sL /dev/sd*`

## Superbloque

El superbloque son los primeros 1024 bytes desde el inicio y se repite en el primer bloque de cada grupo y contiene:

* Tamaño de bloque
* Bloques totales
* Bloques por grupo de bloques
* Bloques reservados antes del primer grupo de bloques
* Inodos totales
* Inodos por grupo de bloques
* Nombre del volumen
* Última hora de escritura
* Última hora de montaje
* Ruta donde se montó el sistema de archivos por última vez
* Estado del sistema de archivos (¿limpio?)

Es posible obtener esta información de un archivo de sistema de archivos Ext usando:
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
También puedes usar la aplicación GUI gratuita: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
O también puedes usar **python** para obtener la información del superbloque: [https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodos

Los **inodos** contienen la lista de **bloques** que **contienen** los **datos** reales de un **archivo**.\
Si el archivo es grande, un inodo **puede contener punteros** a **otros inodos** que apuntan a los bloques/más inodos que contienen los datos del archivo.

![](<../../../.gitbook/assets/image (416).png>)

En **Ext2** y **Ext3** los inodos tienen un tamaño de **128B**, **Ext4** actualmente utiliza **156B** pero asigna **256B** en disco para permitir una futura expansión.

Estructura del inodo:

| Offset | Tamaño | Nombre              | Descripción                                      |
| ------ | ------ | ------------------- | ------------------------------------------------ |
| 0x0    | 2      | Modo de archivo     | Modo y tipo de archivo                           |
| 0x2    | 2      | UID                 | 16 bits inferiores del ID del propietario        |
| 0x4    | 4      | Tamaño Il           | 32 bits inferiores del tamaño del archivo        |
| 0x8    | 4      | Atime               | Tiempo de acceso en segundos desde la época      |
| 0xC    | 4      | Ctime               | Tiempo de cambio en segundos desde la época      |
| 0x10   | 4      | Mtime               | Tiempo de modificación en segundos desde la época|
| 0x14   | 4      | Dtime               | Tiempo de eliminación en segundos desde la época |
| 0x18   | 2      | GID                 | 16 bits inferiores del ID del grupo              |
| 0x1A   | 2      | Conteo de Hlink     | Conteo de enlaces duros                          |
| 0xC    | 4      | Bloques Io          | 32 bits inferiores del conteo de bloques         |
| 0x20   | 4      | Banderas            | Banderas                                         |
| 0x24   | 4      | Unión osd1          | Linux: Versión I                                 |
| 0x28   | 69     | Bloque\[15]         | 15 puntos al bloque de datos                     |
| 0x64   | 4      | Versión             | Versión de archivo para NFS                      |
| 0x68   | 4      | ACL de archivo bajo | 32 bits inferiores de atributos extendidos (ACL, etc) |
| 0x6C   | 4      | Tamaño de archivo alto | 32 bits superiores del tamaño del archivo (solo ext4) |
| 0x70   | 4      | Fragmento obsoleto  | Dirección de fragmento obsoleta                  |
| 0x74   | 12     | Osd 2               | Segunda unión dependiente del sistema operativo  |
| 0x74   | 2      | Bloques alto        | 16 bits superiores del conteo de bloques         |
| 0x76   | 2      | ACL de archivo alto | 16 bits superiores de atributos extendidos (ACL, etc.) |
| 0x78   | 2      | UID alto            | 16 bits superiores del ID del propietario        |
| 0x7A   | 2      | GID alto            | 16 bits superiores del ID del grupo              |
| 0x7C   | 2      | Chequeo Io          | 16 bits inferiores del chequeo del inodo         |

"Modificar" es la marca de tiempo de la última vez que el _contenido_ del archivo ha sido modificado. A menudo se llama "_mtime_".\
"Cambiar" es la marca de tiempo de la última vez que el _inodo_ del archivo ha sido cambiado, como al cambiar permisos, propiedad, nombre del archivo y el número de enlaces duros. A menudo se llama "_ctime_".

Estructura extendida del inodo (Ext4):

| Offset | Tamaño | Nombre         | Descripción                                   |
| ------ | ------ | -------------- | --------------------------------------------- |
| 0x80   | 2      | Tamaño extra   | Cuántos bytes más allá del estándar de 128 se usan |
| 0x82   | 2      | Chequeo alto   | 16 bits superiores del chequeo del inodo      |
| 0x84   | 4      | Ctime extra    | Bits extra del tiempo de cambio               |
| 0x88   | 4      | Mtime extra    | Bits extra del tiempo de modificación         |
| 0x8C   | 4      | Atime extra    | Bits extra del tiempo de acceso               |
| 0x90   | 4      | Crtime         | Tiempo de creación del archivo (segundos desde la época) |
| 0x94   | 4      | Crtime extra   | Bits extra del tiempo de creación del archivo |
| 0x98   | 4      | Versión alta   | 32 bits superiores de la versión              |
| 0x9C   |        | No utilizado   | Espacio reservado para futuras expansiones    |

Inodos especiales:

| Inodo | Propósito Especial                                      |
| ----- | ------------------------------------------------------- |
| 0     | No existe tal inodo, la numeración comienza en 1        |
| 1     | Lista de bloques defectuosos                            |
| 2     | Directorio raíz                                         |
| 3     | Cuotas de usuario                                       |
| 4     | Cuotas de grupo                                         |
| 5     | Cargador de arranque                                    |
| 6     | Directorio de recuperación de archivos eliminados       |
| 7     | Descriptores de grupo reservados (para redimensionar el sistema de archivos) |
| 8     | Diario                                                  |
| 9     | Inodo de exclusión (para instantáneas)                  |
| 10    | Inodo de réplica                                        |
| 11    | Primer inodo no reservado (a menudo perdido + encontrado) |

{% hint style="info" %}
Nota que el tiempo de creación solo aparece en Ext4.
{% endhint %}

Conociendo el número de inodo, puedes encontrar fácilmente su índice:

* **Grupo de bloques** al que pertenece un inodo: (Número de inodo - 1) / (Inodos por grupo)
* **Índice dentro de su grupo**: (Número de inodo - 1) mod(Inodos/grupo)
* **Desplazamiento** en la **tabla de inodos**: Número de inodo \* (Tamaño del inodo)
* El "-1" es porque el inodo 0 no está definido (no se usa)
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
Modo de Archivo

| Número | Descripción                                                                                         |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Directorio/Bloque Bit 13**                                                                        |
| **13** | **Dispositivo Char/Bloque Bit 14**                                                                  |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Sticky Bit (sin él, cualquiera con permisos de escritura y ejecución en un directorio puede eliminar y renombrar archivos) |
| 8      | Lectura del Propietario                                                                             |
| 7      | Escritura del Propietario                                                                           |
| 6      | Ejecución del Propietario                                                                           |
| 5      | Lectura del Grupo                                                                                   |
| 4      | Escritura del Grupo                                                                                 |
| 3      | Ejecución del Grupo                                                                                 |
| 2      | Lectura de Otros                                                                                    |
| 1      | Escritura de Otros                                                                                  |
| 0      | Ejecución de Otros                                                                                  |

Los bits en negrita (12, 13, 14, 15) indican el tipo de archivo que es (un directorio, socket...) solo una de las opciones en negrita puede existir.

Directorios

| Desplazamiento | Tamaño | Nombre      | Descripción                                                                                                                                                  |
| -------------- | ------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0            | 4      | Inode       |                                                                                                                                                              |
| 0x4            | 2      | Long. de reg | Longitud del registro                                                                                                                                        |
| 0x6            | 1      | Long. de nom | Longitud del nombre                                                                                                                                          |
| 0x7            | 1      | Tipo de arch | <p>0x00 Desconocido<br>0x01 Regular</p><p>0x02 Directorio</p><p>0x03 Dispositivo Char</p><p>0x04 Dispositivo Bloque</p><p>0x05 FIFO</p><p>0x06 Socket</p><p>0x07 Enlace Simb</p> |
| 0x8            |        | Nombre       | Cadena de nombre (hasta 255 caracteres)                                                                                                                      |

**Para aumentar el rendimiento, se pueden utilizar bloques de directorio de Hash Raíz.**

**Atributos Extendidos**

Pueden almacenarse en

* Espacio extra entre inodos (256 - tamaño del inodo, usualmente = 100)
* Un bloque de datos señalado por file\_acl en inodo

Pueden utilizarse para almacenar cualquier cosa como un atributo de usuario si el nombre comienza con "user". Así, los datos pueden ocultarse de esta manera.

Entradas de Atributos Extendidos

| Desplazamiento | Tamaño | Nombre         | Descripción                                                                                                                                                                                                        |
| -------------- | ------ | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0            | 1      | Long. de nom   | Longitud del nombre del atributo                                                                                                                                                                                   |
| 0x1            | 1      | Índice de nom  | <p>0x0 = sin prefijo</p><p>0x1 = usuario. Prefijo</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = confiable.</p><p>0x6 = seguridad.</p><p>0x7 = sistema.</p><p>0x8 = system.richacl</p> |
| 0x2            | 2      | Despl. de val  | Desplazamiento desde la primera entrada de inodo o inicio de bloque                                                                                                                                                 |
| 0x4            | 4      | Bloques de val | Bloque de disco donde se almacena el valor o cero para este bloque                                                                                                                                                  |
| 0x8            | 4      | Tamaño de val  | Longitud del valor                                                                                                                                                                                                  |
| 0xC            | 4      | Hash           | Hash para atributos en bloque o cero si está en inodo                                                                                                                                                               |
| 0x10           |        | Nombre         | Nombre del atributo sin NULL al final                                                                                                                                                                               |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## Vista del Sistema de Archivos

Para ver el contenido del sistema de archivos, puedes **usar la herramienta gratuita**: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
O puedes montarlo en tu linux usando el comando `mount`.

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
