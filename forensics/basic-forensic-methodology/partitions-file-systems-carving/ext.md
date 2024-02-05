<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Ext - Sistema de archivos extendido

**Ext2** es el sistema de archivos más común para **particiones sin registro** (**particiones que no cambian mucho**) como la partición de arranque. **Ext3/4** son **con registro** y se utilizan generalmente para las **otras particiones**.

Todos los grupos de bloques en el sistema de archivos tienen el mismo tamaño y se almacenan de forma secuencial. Esto permite al kernel derivar fácilmente la ubicación de un grupo de bloques en un disco a partir de su índice entero.

Cada grupo de bloques contiene la siguiente información:

* Una copia del superbloque del sistema de archivos
* Una copia de los descriptores del grupo de bloques
* Un mapa de bits de bloques de datos que se utiliza para identificar los bloques libres dentro del grupo
* Un mapa de bits de inodos, que se utiliza para identificar los inodos libres dentro del grupo
* tabla de inodos: consta de una serie de bloques consecutivos, cada uno de los cuales contiene un número predefinido de inodos de la Figura 1 Ext2. Todos los inodos tienen el mismo tamaño: 128 bytes. Un bloque de 1,024 bytes contiene 8 inodos, mientras que un bloque de 4,096 bytes contiene 32 inodos. Tenga en cuenta que en Ext2, no es necesario almacenar en disco un mapeo entre un número de inodo y el número de bloque correspondiente porque el último valor se puede derivar del número de grupo de bloques y la posición relativa dentro de la tabla de inodos. Por ejemplo, supongamos que cada grupo de bloques contiene 4,096 inodos y que queremos conocer la dirección en el disco del inodo 13,021. En este caso, el inodo pertenece al tercer grupo de bloques y su dirección en disco se almacena en la 733ª entrada de la tabla de inodos correspondiente. Como puede ver, el número de inodo es solo una clave utilizada por las rutinas de Ext2 para recuperar rápidamente el descriptor de inodo adecuado en el disco
* bloques de datos, que contienen archivos. Cualquier bloque que no contenga información significativa se considera libre.

![](<../../../.gitbook/assets/image (406).png>)

## Características opcionales de Ext

**Las características afectan dónde** se encuentra los datos, **cómo** se almacenan los datos en los inodos y algunas de ellas podrían proporcionar **metadatos adicionales** para el análisis, por lo tanto, las características son importantes en Ext.

Ext tiene características opcionales que su sistema operativo puede o no admitir, hay 3 posibilidades:

* Compatible
* Incompatible
* Compatible solo lectura: Se puede montar pero no para escribir

Si hay características **incompatibles**, no podrás montar el sistema de archivos ya que el sistema operativo no sabrá cómo acceder a los datos.

{% hint style="info" %}
Un atacante sospechoso podría tener extensiones no estándar
{% endhint %}

**Cualquier utilidad** que lea el **superbloque** podrá indicar las **características** de un **sistema de archivos Ext**, pero también podrías usar `file -sL /dev/sd*`

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

Es posible obtener esta información de un archivo de sistema de archivos Ext utilizando:
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
Puedes usar la aplicación GUI gratuita: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
O también puedes usar **python** para obtener la información del superbloque: [https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodos

Los **inodos** contienen la lista de **bloques** que **contienen** los datos reales de un **archivo**.\
Si el archivo es grande, un inodo **puede contener punteros** a **otros inodos** que apuntan a los bloques/más inodos que contienen los datos del archivo.

![](<../../../.gitbook/assets/image (416).png>)

En **Ext2** y **Ext3** los inodos tienen un tamaño de **128B**, **Ext4** actualmente usa **156B** pero asigna **256B** en disco para permitir una expansión futura.

Estructura del inodo:

| Offset | Tamaño | Nombre            | Descripción                                      |
| ------ | ------ | ----------------- | ------------------------------------------------ |
| 0x0    | 2      | Modo de archivo   | Modo de archivo y tipo                           |
| 0x2    | 2      | UID               | 16 bits inferiores del ID del propietario        |
| 0x4    | 4      | Tamaño Il         | 32 bits inferiores del tamaño del archivo        |
| 0x8    | 4      | Atime             | Tiempo de acceso en segundos desde la época      |
| 0xC    | 4      | Ctime             | Tiempo de cambio en segundos desde la época      |
| 0x10   | 4      | Mtime             | Tiempo de modificación en segundos desde la época|
| 0x14   | 4      | Dtime             | Tiempo de eliminación en segundos desde la época |
| 0x18   | 2      | GID               | 16 bits inferiores del ID de grupo               |
| 0x1A   | 2      | Recuento de enlaces duros | Cantidad de enlaces duros                  |
| 0xC    | 4      | Bloques Io        | 32 bits inferiores del recuento de bloques       |
| 0x20   | 4      | Banderas          | Banderas                                         |
| 0x24   | 4      | Unión osd1        | Linux: versión I                                 |
| 0x28   | 69     | Bloque\[15]       | 15 puntos al bloque de datos                    |
| 0x64   | 4      | Versión           | Versión del archivo para NFS                     |
| 0x68   | 4      | ACL de archivo bajo | 32 bits inferiores de atributos extendidos (ACL, etc) |
| 0x6C   | 4      | Tamaño de archivo alto | 32 bits superiores del tamaño del archivo (solo ext4) |
| 0x70   | 4      | Fragmento obsoleto | Una dirección de fragmento obsoleta              |
| 0x74   | 12     | Osd 2             | Segunda unión dependiente del sistema operativo  |
| 0x74   | 2      | Bloques altos     | 16 bits superiores del recuento de bloques       |
| 0x76   | 2      | ACL de archivo alto | 16 bits superiores de atributos extendidos (ACL, etc) |
| 0x78   | 2      | UID alto          | 16 bits superiores del ID del propietario        |
| 0x7A   | 2      | GID alto          | 16 bits superiores del ID de grupo               |
| 0x7C   | 2      | Suma de comprobación Io | 16 bits inferiores de la suma de comprobación del inodo |

"Modificar" es la marca de tiempo de la última vez que el _contenido_ del archivo ha sido modificado. A menudo se llama "_mtime_".\
"Cambiar" es la marca de tiempo de la última vez que el _inodo_ del archivo ha sido cambiado, como al cambiar permisos, propiedad, nombre de archivo y el número de enlaces duros. A menudo se llama "_ctime_".

Estructura extendida del inodo (Ext4):

| Offset | Tamaño | Nombre         | Descripción                                 |
| ------ | ------ | -------------- | ------------------------------------------- |
| 0x80   | 2      | Tamaño extra   | Cuántos bytes más allá de los 128 estándar se utilizan |
| 0x82   | 2      | Suma de comprobación alta | 16 bits superiores de la suma de comprobación del inodo |
| 0x84   | 4      | Ctime extra    | Bits extra de tiempo de cambio               |
| 0x88   | 4      | Mtime extra    | Bits extra de tiempo de modificación         |
| 0x8C   | 4      | Atime extra    | Bits extra de tiempo de acceso               |
| 0x90   | 4      | Crtime         | Tiempo de creación del archivo (segundos desde la época) |
| 0x94   | 4      | Crtime extra   | Bits extra de tiempo de creación del archivo |
| 0x98   | 4      | Versión alta   | 32 bits superiores de la versión             |
| 0x9C   |        | No utilizado   | Espacio reservado para expansiones futuras   |

Inodos especiales:

| Inodo | Propósito especial                                   |
| ----- | ---------------------------------------------------- |
| 0     | No existe tal inodo, la numeración comienza en 1     |
| 1     | Lista de bloques defectuosos                         |
| 2     | Directorio raíz                                      |
| 3     | Cuotas de usuario                                    |
| 4     | Cuotas de grupo                                      |
| 5     | Cargador de arranque                                 |
| 6     | Directorio de recuperación                           |
| 7     | Descriptores de grupo reservados (para cambiar el tamaño del sistema de archivos) |
| 8     | Diario                                               |
| 9     | Inodo excluido (para instantáneas)                   |
| 10    | Inodo de réplica                                     |
| 11    | Primer inodo no reservado (a menudo lost + found)    |

{% hint style="info" %}
Nota que la hora de creación solo aparece en Ext4.
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
### Modo de Archivo

| Número | Descripción                                                                                         |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Directorio/Bit de Bloque 13**                                                                     |
| **13** | **Dispositivo de Carácter/Bit de Bloque 14**                                                        |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Bit Sticky (sin él, cualquiera con permisos de escritura y ejecución en un directorio puede eliminar y renombrar archivos) |
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

### Directorios

| Desplazamiento | Tamaño | Nombre    | Descripción                                                                                                                                                  |
| ------ | ---- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 4    | Inodo     |                                                                                                                                                              |
| 0x4    | 2    | Longitud de Registro   | Longitud del registro                                                                                                                                                |
| 0x6    | 1    | Longitud del Nombre  | Longitud del nombre                                                                                                                                                  |
| 0x7    | 1    | Tipo de Archivo | <p>0x00 Desconocido<br>0x01 Regular</p><p>0x02 Directorio</p><p>0x03 Dispositivo de Carácter</p><p>0x04 Dispositivo de Bloque</p><p>0x05 FIFO</p><p>0x06 Socket</p><p>0x07 Enlace Símbolico</p> |
| 0x8    |      | Nombre      | Cadena de nombre (hasta 255 caracteres)                                                                                                                           |

**Para aumentar el rendimiento, se pueden utilizar bloques de directorio de hash raíz.**

### Atributos Extendidos

Pueden ser almacenados en

* Espacio adicional entre inodos (256 - tamaño de inodo, generalmente = 100)
* Un bloque de datos apuntado por file\_acl en el inodo

Se pueden usar para almacenar cualquier cosa como un atributo de usuario si el nombre comienza con "user". De esta manera, los datos pueden estar ocultos.

Entradas de Atributos Extendidos

| Desplazamiento | Tamaño | Nombre         | Descripción                                                                                                                                                                                                        |
| ------ | ---- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 1    | Longitud del Nombre     | Longitud del nombre del atributo                                                                                                                                                                                           |
| 0x1    | 1    | Índice del Nombre   | <p>0x0 = sin prefijo</p><p>0x1 = prefijo user.</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2    | Desplazamiento del Valor   | Desplazamiento desde la primera entrada de inodo o inicio del bloque                                                                                                                                                                    |
| 0x4    | 4    | Bloques de Valor | Bloque de disco donde se almacena el valor o cero para este bloque                                                                                                                                                               |
| 0x8    | 4    | Tamaño del Valor   | Longitud del valor                                                                                                                                                                                                    |
| 0xC    | 4    | Hash         | Hash para atributos en el bloque o cero si está en el inodo                                                                                                                                                                      |
| 0x10   |      | Nombre         | Nombre del atributo sin NULL final                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## Vista del sistema de archivos

Para ver el contenido del sistema de archivos, puedes **utilizar la herramienta gratuita**: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
O puedes montarlo en tu Linux usando el comando `mount`.

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=El%20sistema%20de%20archivos%20Ext2%20divide,tiempo%20promedio%20de%20búsqueda%20en%20disco.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=El%20sistema%20de%20archivos%20Ext2%20divide,tiempo%20promedio%20de%20búsqueda%20en%20disco.)
