# Ext - Sistema de archivos extendido

**Ext2** es el sistema de archivos más común para particiones **sin registro** (**particiones que no cambian mucho**) como la partición de arranque. **Ext3/4** son **con registro** y se usan generalmente para las **otras particiones**.

Todos los grupos de bloques en el sistema de archivos tienen el mismo tamaño y se almacenan secuencialmente. Esto permite al kernel derivar fácilmente la ubicación de un grupo de bloques en un disco a partir de su índice entero.

Cada grupo de bloques contiene la siguiente información:

* Una copia del superbloque del sistema de archivos
* Una copia de los descriptores del grupo de bloques
* Un mapa de bits de bloque de datos que se utiliza para identificar los bloques libres dentro del grupo
* Un mapa de bits de inodo, que se utiliza para identificar los inodos libres dentro del grupo
* Tabla de inodos: consta de una serie de bloques consecutivos, cada uno de los cuales contiene un número de inodo de Ext2 predefinido. Todos los inodos tienen el mismo tamaño: 128 bytes. Un bloque de 1.024 bytes contiene 8 inodos, mientras que un bloque de 4.096 bytes contiene 32 inodos. Tenga en cuenta que en Ext2 no es necesario almacenar en disco un mapeo entre un número de inodo y el número de bloque correspondiente porque este último valor se puede derivar del número de grupo de bloques y la posición relativa dentro de la tabla de inodos. Por ejemplo, supongamos que cada grupo de bloques contiene 4.096 inodos y que queremos conocer la dirección en el disco del inodo 13.021. En este caso, el inodo pertenece al tercer grupo de bloques y su dirección en el disco se almacena en la entrada 733 de la tabla de inodos correspondiente. Como puede ver, el número de inodo es solo una clave que utilizan las rutinas de Ext2 para recuperar rápidamente el descriptor de inodo adecuado en el disco.
* bloques de datos, que contienen archivos. Cualquier bloque que no contenga información significativa se dice que está libre.

![](<../../../.gitbook/assets/image (406).png>)

## Características opcionales de Ext

Las **características afectan dónde** se encuentra la información, **cómo** se almacena la información en los inodos y algunas de ellas pueden proporcionar **metadatos adicionales** para el análisis, por lo tanto, las características son importantes en Ext.

Ext tiene características opcionales que su sistema operativo puede o no admitir, hay 3 posibilidades:

* Compatible
* Incompatible
* Compatible solo lectura: se puede montar pero no para escribir

Si hay **características incompatibles**, no podrá montar el sistema de archivos ya que el sistema operativo no sabrá cómo acceder a los datos.

{% hint style="info" %}
Un atacante sospechoso podría tener extensiones no estándar
{% endhint %}

**Cualquier utilidad** que lea el **superbloque** podrá indicar las **características** de un **sistema de archivos Ext**, pero también se puede usar `file -sL /dev/sd*` para obtener esta información.

## Superbloque

El superbloque es los primeros 1024 bytes desde el inicio y se repite en el primer bloque de cada grupo y contiene:

* Tamaño de bloque
* Bloques totales
* Bloques por grupo de bloques
* Bloques reservados antes del primer grupo de bloques
* Inodos totales
* Inodos por grupo de bloques
* Nombre del volumen
* Última hora de escritura
* Última hora de montaje
* Ruta donde se montó por última vez el sistema de archivos
* Estado del sistema de archivos (¿limpio?)

Es posible obtener esta información de un archivo de sistema de archivos Ext usando:
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
También puedes utilizar la aplicación GUI gratuita: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
O también puedes usar **python** para obtener la información del superbloque: [https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodos

Los **inodos** contienen la lista de **bloques** que **contienen** los datos reales de un **archivo**.\
Si el archivo es grande, un inodo **puede contener punteros** a **otros inodos** que apuntan a los bloques/más inodos que contienen los datos del archivo.

![](<../../../.gitbook/assets/image (416).png>)

En **Ext2** y **Ext3**, los inodos tienen un tamaño de **128B**, **Ext4** actualmente usa **156B** pero asigna **256B** en el disco para permitir una expansión futura.

Estructura del inodo:

| Offset | Tamaño | Nombre            | Descripción                                      |
| ------ | ------ | ----------------- | ------------------------------------------------ |
| 0x0    | 2      | Modo de archivo   | Modo y tipo de archivo                           |
| 0x2    | 2      | UID               | 16 bits inferiores del ID del propietario        |
| 0x4    | 4      | Tamaño Il         | 32 bits inferiores del tamaño del archivo        |
| 0x8    | 4      | Atime             | Hora de acceso en segundos desde la época        |
| 0xC    | 4      | Ctime             | Hora de cambio en segundos desde la época        |
| 0x10   | 4      | Mtime             | Hora de modificación en segundos desde la época  |
| 0x14   | 4      | Dtime             | Hora de eliminación en segundos desde la época   |
| 0x18   | 2      | GID               | 16 bits inferiores del ID del grupo              |
| 0x1A   | 2      | Contador de enlace | Contador de enlaces duros                         |
| 0xC    | 4      | Bloques Io        | 32 bits inferiores del recuento de bloques       |
| 0x20   | 4      | Banderas          | Banderas                                         |
| 0x24   | 4      | Unión osd1       | Linux: versión I                                 |
| 0x28   | 69     | Bloque\[15]       | 15 puntos al bloque de datos                     |
| 0x64   | 4      | Versión           | Versión de archivo para NFS                       |
| 0x68   | 4      | Archivo ACL bajo  | 32 bits inferiores de atributos extendidos (ACL, etc.) |
| 0x6C   | 4      | Tamaño de archivo hi | 32 bits superiores del tamaño del archivo (solo ext4) |
| 0x70   | 4      | Fragmento obsoleto | Una dirección de fragmento obsoleta               |
| 0x74   | 12     | Osd 2             | Segunda unión dependiente del sistema operativo  |
| 0x74   | 2      | Bloques hi        | 16 bits superiores del recuento de bloques        |
| 0x76   | 2      | Archivo ACL hi    | 16 bits superiores de atributos extendidos (ACL, etc.) |
| 0x78   | 2      | UID hi            | 16 bits superiores del ID del propietario         |
| 0x7A   | 2      | GID hi            | 16 bits superiores del ID del grupo               |
| 0x7C   | 2      | Checksum Io       | 16 bits inferiores del checksum del inodo        |

"Modificar" es la marca de tiempo de la última vez que se ha modificado el contenido del archivo. A menudo se llama "_mtime_".\
"Cambiar" es la marca de tiempo de la última vez que se ha cambiado el inodo del archivo, como al cambiar los permisos, la propiedad, el nombre del archivo y el número de enlaces duros. A menudo se llama "_ctime_".

Estructura extendida del inodo (Ext4):

| Offset | Tamaño | Nombre        | Descripción                                        |
| ------ | ------ | ------------- | -------------------------------------------------- |
| 0x80   | 2      | Tamaño extra  | Cuántos bytes más allá de los 128 estándar se usan |
| 0x82   | 2      | Checksum hi   | 16 bits superiores del checksum del inodo          |
| 0x84   | 4      | Ctime extra   | Bits adicionales de tiempo de cambio                |
| 0x88   | 4      | Mtime extra   | Bits adicionales de tiempo de modificación          |
| 0x8C   | 4      | Atime extra   | Bits adicionales de tiempo de acceso                |
| 0x90   | 4      | Crtime        | Hora de creación del archivo (segundos desde la época) |
| 0x94   | 4      | Crtime extra  | Bits adicionales de tiempo de creación              |
| 0x98   | 4      | Versión hi    | 32 bits superiores de la versión                   |
| 0x9C   |        | Sin usar      | Espacio reservado para futuras expansiones          |

Inodos especiales:

| Inodo | Propósito especial                                   |
| ----- | ---------------------------------------------------- |
| 0     | No hay tal inodo, la numeración comienza en 1        |
| 1     | Lista de bloques defectuosos                         |
| 2     | Directorio raíz                                      |
| 3     | Cuotas de usuario                                    |
| 4     | Cuotas de grupo                                      |
| 5     | Cargador de arranque                                  |
| 6     | Directorio de recuperación                            |
| 7     | Descriptores de grupo reservados (para cambiar el tamaño del sistema de archivos) |
| 8     | Diario                                               |
| 9     | Excluir inodo (para instantáneas)                     |
| 10    | Inodo de réplica                                     |
| 11    | Primer inodo no reservado (a menudo perdido + encontrado) |

{% hint style="info" %}
Tenga en cuenta que la hora de creación solo aparece en Ext4.
{% endhint %}

Al conocer el número de inodo, puedes encontrar fácilmente su índice:

* **Grupo de bloques** al que pertenece un inodo: (Número de inodo - 1) / (Inodos por grupo)
* **Índice dentro de su grupo**: (Número de inodo - 1) mod (Inodos/grupos)
* **Desplazamiento** en la **tabla de inodos**: Número de inodo \* (Tamaño de inodo)
* El "-1" es porque el inodo 0 no está definido (no se usa)
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
Modo de archivo

| Número | Descripción                                                                                         |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Directorio/Bit de bloque 13**                                                                     |
| **13** | **Dispositivo de caracteres/Bit de bloque 14**                                                      |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Bit pegajoso (sin él, cualquier persona con permisos de escritura y ejecución en un directorio puede eliminar y renombrar archivos) |
| 8      | Lectura del propietario                                                                             |
| 7      | Escritura del propietario                                                                           |
| 6      | Ejecución del propietario                                                                           |
| 5      | Lectura del grupo                                                                                   |
| 4      | Escritura del grupo                                                                                 |
| 3      | Ejecución del grupo                                                                                 |
| 2      | Lectura de otros                                                                                    |
| 1      | Escritura de otros                                                                                   |
| 0      | Ejecución de otros                                                                                  |

Los bits en negrita (12, 13, 14, 15) indican el tipo de archivo que es el archivo (un directorio, un socket...) solo una de las opciones en negrita puede existir.

Directorios

| Offset | Tamaño | Nombre    | Descripción                                                                                                                                                  |
| ------ | ------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 4      | Inodo     |                                                                                                                                                              |
| 0x4    | 2      | Longitud de registro | Longitud del registro                                                                                                                                                |
| 0x6    | 1      | Longitud del nombre | Longitud del nombre                                                                                                                                                  |
| 0x7    | 1      | Tipo de archivo | <p>0x00 Desconocido<br>0x01 Regular</p><p>0x02 Directorio</p><p>0x03 Dispositivo de caracteres</p><p>0x04 Dispositivo de bloque</p><p>0x05 FIFO</p><p>0x06 Socket</p><p>0x07 Enlace simbólico</p> |
| 0x8    |        | Nombre    | Cadena de nombre (hasta 255 caracteres)                                                                                                                           |

**Para aumentar el rendimiento, se pueden utilizar bloques de directorio hash raíz.**

**Atributos extendidos**

Pueden ser almacenados en

* Espacio extra entre inodos (256 - tamaño de inodo, generalmente = 100)
* Un bloque de datos apuntado por file\_acl en el inodo

Se pueden usar para almacenar cualquier cosa como atributo de usuario si el nombre comienza con "usuario". Por lo tanto, los datos se pueden ocultar de esta manera.

Entradas de atributos extendidos

| Offset | Tamaño | Nombre         | Descripción                                                                                                                                                                                                        |
| ------ | ------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 1      | Longitud del nombre     | Longitud del nombre del atributo                                                                                                                                                                                           |
| 0x1    | 1      | Índice de nombre   | <p>0x0 = sin prefijo</p><p>0x1 = prefijo de usuario</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2      | Desplazamiento del valor   | Desplazamiento desde la primera entrada de inodo o el inicio del bloque                                                                                                                                                                    |
| 0x4    | 4      | Bloques de valor | Bloque de disco donde se almacena el valor o cero para este bloque                                                                                                                                                               |
| 0x8    | 4      | Tamaño del valor   | Longitud del valor                                                                                                                                                                                                    |
| 0xC    | 4      | Hash         | Hash para atributos en bloque o cero si está en inodo                                                                                                                                                                      |
| 0x10   |        | Nombre         | Nombre del atributo sin NULL final                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## Vista del sistema de archivos

Para ver el contenido del sistema de archivos, puedes **usar la herramienta gratuita**: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
O puedes montarlo en tu linux usando el comando `mount`.

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=El%20sistema%20de%20archivos%20Ext2%20divide,tiempo%20promedio%20de%20búsqueda%20en%20disco.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=El%20sistema%20de%20archivos%20Ext2%20divide,tiempo%20promedio%20de%20búsqueda%20en%20disco.)
