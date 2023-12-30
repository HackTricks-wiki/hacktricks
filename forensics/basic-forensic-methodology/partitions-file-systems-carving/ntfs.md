# NTFS

## NTFS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **NTFS**

**NTFS** (**New Technology File System**) es un sistema de archivos con registro de transacciones propietario desarrollado por Microsoft.

El clúster es la unidad más pequeña de tamaño en NTFS y el tamaño del clúster depende del tamaño de una partición.

| Tamaño de la partición   | Sectores por clúster | Tamaño del clúster |
| ------------------------ | ------------------- | ------------ |
| 512MB o menos            | 1                   | 512 bytes    |
| 513MB-1024MB (1GB)       | 2                   | 1KB          |
| 1025MB-2048MB (2GB)      | 4                   | 2KB          |
| 2049MB-4096MB (4GB)      | 8                   | 4KB          |
| 4097MB-8192MB (8GB)      | 16                  | 8KB          |
| 8193MB-16,384MB (16GB)   | 32                  | 16KB         |
| 16,385MB-32,768MB (32GB) | 64                  | 32KB         |
| Más de 32,768MB          | 128                 | 64KB         |

### **Espacio Sobrante**

Como la **unidad más pequeña** de tamaño de NTFS es un **clúster**. Cada archivo ocupará varios clústeres completos. Entonces, es muy probable que **cada archivo ocupe más espacio del necesario**. Estos **espacios no utilizados** **reservados** por un archivo se llaman **espacio sobrante** y las personas podrían aprovechar esta área para **ocultar** **información**.

![](<../../../.gitbook/assets/image (498).png>)

### **Sector de arranque de NTFS**

Cuando formateas un volumen NTFS, el programa de formato asigna los primeros 16 sectores para el archivo de metadatos de arranque. El primer sector es un sector de arranque con un código de "bootstrap" y los siguientes 15 sectores son el IPL (Cargador de Programa Inicial) del sector de arranque. Para aumentar la fiabilidad del sistema de archivos, el último sector de una partición NTFS contiene una copia de reserva del sector de arranque.

### **Tabla de Archivos Maestros (MFT)**

El sistema de archivos NTFS contiene un archivo llamado Tabla de Archivos Maestros (MFT). Hay al menos **una entrada en la MFT para cada archivo en un volumen del sistema de archivos NTFS**, incluida la propia MFT. Toda la información sobre un archivo, incluyendo su **tamaño, marcas de tiempo y fecha, permisos y contenido de datos**, se almacena ya sea en entradas de la MFT o en espacio fuera de la MFT que es descrito por entradas de la MFT.

A medida que se **agregan archivos** a un volumen del sistema de archivos NTFS, se agregan más entradas a la MFT y la **MFT aumenta de tamaño**. Cuando los **archivos** son **eliminados** de un volumen del sistema de archivos NTFS, sus **entradas de la MFT se marcan como libres** y pueden ser reutilizadas. Sin embargo, el espacio en disco que ha sido asignado para estas entradas no se reasigna, y el tamaño de la MFT no disminuye.

El sistema de archivos NTFS **reserva espacio para la MFT para mantener la MFT lo más contigua posible** a medida que crece. El espacio reservado por el sistema de archivos NTFS para la MFT en cada volumen se llama la **zona MFT**. El espacio para archivos y directorios también se asigna desde este espacio, pero solo después de que todo el espacio del volumen fuera de la zona MFT haya sido asignado.

Dependiendo del tamaño promedio de archivo y otras variables, **o bien la zona MFT reservada o el espacio no reservado en el disco pueden ser asignados primero a medida que el disco se llena hasta su capacidad**. Los volúmenes con un pequeño número de archivos relativamente grandes asignarán primero el espacio no reservado, mientras que los volúmenes con un gran número de archivos relativamente pequeños asignarán primero la zona MFT. En cualquier caso, la fragmentación de la MFT comienza a tener lugar cuando una región u otra se asigna completamente. Si el espacio no reservado está completamente asignado, el espacio para archivos y directorios de usuario se asignará desde la zona MFT. Si la zona MFT está completamente asignada, el espacio para nuevas entradas de la MFT se asignará desde el espacio no reservado.

Los sistemas de archivos NTFS también generan un **$MFTMirror**. Esto es una **copia** de las **primeras 4 entradas** de la MFT: $MFT, $MFT Mirror, $Log, $Volume.

NTFS reserva los primeros 16 registros de la tabla para información especial:

| Archivo del Sistema     | Nombre del Archivo | Registro MFT | Propósito del Archivo                                                                                                                                                                                                           |
| --------------------- | --------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tabla de archivos maestros     | $Mft      | 0          | Contiene un registro de archivo base para cada archivo y carpeta en un volumen NTFS. Si la información de asignación para un archivo o carpeta es demasiado grande para caber dentro de un solo registro, se asignan otros registros de archivo también.            |
| Tabla de archivos maestros 2   | $MftMirr  | 1          | Una imagen duplicada de los primeros cuatro registros de la MFT. Este archivo garantiza el acceso a la MFT en caso de un fallo de un solo sector.                                                                                            |
| Archivo de registro              | $LogFile  | 2          | Contiene una lista de pasos de transacción utilizados para la recuperabilidad de NTFS. El tamaño del archivo de registro depende del tamaño del volumen y puede ser tan grande como 4 MB. Se utiliza por Windows NT/2000 para restaurar la consistencia de NTFS después de un fallo del sistema. |
| Volumen                | $Volume   | 3          | Contiene información sobre el volumen, como la etiqueta del volumen y la versión del volumen.                                                                                                                                       |
| Definiciones de atributos | $AttrDef  | 4          | Una tabla de nombres de atributos, números y descripciones.                                                                                                                                                                        |
| Índice de nombres de archivo raíz  | $         | 5          | La carpeta raíz.                                                                                                                                                                                                              |
| Mapa de bits del clúster        | $Bitmap   | 6          | Una representación del volumen que muestra qué clústeres están en uso.                                                                                                                                                             |
| Sector de arranque           | $Boot     | 7          | Incluye el BPB utilizado para montar el volumen y código adicional del cargador de arranque utilizado si el volumen es arrancable.                                                                                                                |
| Archivo de clúster malo      | $BadClus  | 8          | Contiene clústeres malos para el volumen.                                                                                                                                                                                         |
| Archivo de seguridad         | $Secure   | 9          | Contiene descriptores de seguridad únicos para todos los archivos dentro de un volumen.                                                                                                                                                           |
| Tabla de mayúsculas          | $Upcase   | 10         | Convierte caracteres en minúsculas a caracteres Unicode en mayúsculas correspondientes.                                                                                                                                                       |
| Archivo de extensión de NTFS   | $Extend   | 11         | Utilizado para varias extensiones opcionales como cuotas, datos de punto de reanálisis y identificadores de objetos.                                                                                                                              |
|                       |           | 12-15      | Reservado para uso futuro.                                                                                                                                                                                                      |
| Archivo de gestión de cuotas | $Quota    | 24         | Contiene límites de cuota asignados por el usuario en el espacio del volumen.                                                                                                                                                                      |
| Archivo de identificación de objeto        | $ObjId    | 25         | Contiene identificadores únicos de objeto de archivo.                                                                                                                                                                                                     |
| Archivo de punto de reanálisis    | $Reparse  | 26         | Este archivo contiene información sobre archivos y carpetas en el volumen incluyendo datos de punto de reanálisis.                                                                                                                            |

### Cada entrada de la MFT se ve como sigue:

![](<../../../.gitbook/assets/image (499).png>)

Nota cómo cada entrada comienza con "FILE". Cada entrada ocupa 1024 bits. Así que después de 1024 bits desde el inicio de una entrada de la MFT, encontrarás la siguiente.

Usando el [**Active Disk Editor**](https://www.disk-editor.org/index.html) es muy fácil inspeccionar la entrada de un archivo en la MFT. Simplemente haz clic derecho en el archivo y luego haz clic en "Inspect File Record"

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

Revisando la bandera **"En uso"** es muy fácil saber si un archivo fue eliminado (un valor de **0x0 significa eliminado**).

![](<../../../.gitbook/assets/image (510).png>)

También es posible recuperar archivos eliminados usando FTKImager:

![](<../../../.gitbook/assets/image (502).png>)

### Atributos de la MFT

Cada entrada de la MFT tiene varios atributos como indica la siguiente imagen:

![](<../../../.gitbook/assets/image (506).png>)

Cada atributo indica alguna información de la entrada identificada por el tipo:

| Identificador de Tipo | Nombre                     | Descripción                                                                                                       |
| --------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| 16              | $STANDARD\_INFORMATION   | Información general, como banderas; las últimas veces de acceso, escritura y creación; y el propietario y el ID de seguridad. |
| 32              | $ATTRIBUTE\_LIST         | Lista donde se pueden encontrar otros atributos para un archivo.                                                              |
| 48              | $FILE\_NAME              | Nombre del archivo, en Unicode, y las últimas veces de acceso, escritura y creación.                                         |
| 64              | $VOLUME\_VERSION         | Información del volumen. Existe solo en la versión 1.2 (Windows NT).                                                      |
| 64              | $OBJECT\_ID              | Un identificador único de 16 bytes para el archivo o directorio. Existe solo en versiones 3.0+ y posteriores (Windows 2000+).    |
| 80              | $SECURITY\_ DESCRIPTOR   | Las propiedades de control de acceso y seguridad del archivo.                                                           |
| 96              | $VOLUME\_NAME            | Nombre del volumen.                                                                                                      |
| 112             | $VOLUME\_ INFORMATION    | Versión del sistema de archivos y otras banderas.                                                                              |
| 128             | $DATA                    | Contenidos del archivo.                                                                                                    |
| 144             | $INDEX\_ROOT             | Nodo raíz de un árbol de índices.                                                                                       |
| 160             | $INDEX\_ALLOCATION       | Nodos de un árbol de índices arraigado en el atributo $INDEX\_ROOT.                                                          |
| 176             | $BITMAP                  | Un mapa de bits para el archivo $MFT y para índices.                                                                       |
| 192             | $SYMBOLIC\_LINK          | Información de enlace simbólico. Existe solo en la versión 1.2 (Windows NT).                                                   |
| 192             | $REPARSE\_POINT          | Contiene datos sobre un punto de reanálisis, que se utiliza como un enlace simbólico en la versión 3.0+ (Windows 2000+).                |
| 208             | $EA\_INFORMATION         | Utilizado para compatibilidad con aplicaciones de OS/2 (HPFS).                                                    |
| 224             | $EA                      | Utilizado para compatibilidad con aplicaciones de OS/2 (HPFS).                                                    |
| 256             | $LOGGED\_UTILITY\_STREAM | Contiene claves e información sobre atributos encriptados en la versión 3.0+ (Windows 2000+).                         |

Por ejemplo, el **tipo 48 (0x30)** identifica el **nombre del archivo**:

![](<../../../.gitbook/assets/image (508).png>)

También es útil entender que **estos atributos pueden ser residentes** (es decir, existen dentro de un registro MFT dado) o **no residentes** (es decir, existen fuera de un registro MFT dado, en otro lugar del disco, y simplemente se hacen referencia dentro del registro). Por ejemplo, si el atributo **$Data es residente**, esto significa que el **archivo completo se guarda en la MFT**, si es no residente, entonces el contenido del archivo está en otra parte del sistema de archivos.

Algunos atributos interesantes:

* [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard\_information.html) (entre otros):
* Fecha de creación
* Fecha de modificación
* Fecha de acceso
* Fecha de actualización de la MFT
* Permisos de archivo DOS
* [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file\_name.html) (entre otros):
* Nombre del archivo
* Fecha de creación
* Fecha de modificación
* Fecha de acceso
* Fecha de actualización de la MFT
* Tamaño asignado
* Tamaño real
* [Referencia de archivo](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html) al directorio padre.
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html) (entre otros):
* Contiene los datos del archivo o la indicación de los sectores donde residen los datos. En el siguiente ejemplo, el atributo de datos no es residente, por lo que el atributo da información sobre los sectores donde residen los datos.

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)

### Sellos de tiempo de NTFS

![](<../../../.gitbook/assets/image (512).png>)

Otra herramienta útil para analizar la MFT es [**MFT2csv**](https://github.com/jschicht/Mft2Csv) (selecciona el archivo mft o la imagen y presiona dump all y extract para extraer todos los objetos).\
Este programa extraerá todos los datos de la MFT y los presentará en formato CSV. También se puede utilizar para volcar archivos.

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

El archivo **`$LOGFILE`** contiene **registros** sobre las **acciones** que se han **realizado** **en** **archivos**. También **guarda** la **acción** que necesitaría realizar en caso de un **rehacer** y la acción necesaria para **volver** al **estado** **anterior**.\
Estos registros son útiles para la MFT para reconstruir el sistema de archivos en caso de que ocurra algún tipo de error. El tamaño máximo de este archivo es **65536KB**.

Para inspeccionar el `$LOGFILE` necesitas extraerlo e inspeccionar previamente el `$MFT` con [**MFT2csv**](https://github.com/jschicht/Mft2Csv).\
Luego ejecuta [**LogFileParser**](https://github.com/jschicht/LogFileParser) contra este archivo y selecciona el archivo `$LOGFILE` exportado y el CVS de la inspección del `$MFT`. Obtendrás un archivo CSV con los registros de la actividad del sistema de archivos grabados por el registro `$LOGFILE`.

![](<../../../.gitbook/assets/image (515).png>)

Filtrando por nombres de archivo puedes ver **todas las acciones realizadas contra un archivo**:

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

El archivo `$EXTEND/$USNJnrl/$J` es un flujo de datos alternativo del archivo `$EXTEND$USNJnrl`. Este artefacto contiene un **registro de cambios producidos dentro del volumen NTFS con más detalle que `$LOGFILE`**.

Para inspeccionar este
