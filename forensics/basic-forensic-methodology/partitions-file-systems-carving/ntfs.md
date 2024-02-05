# NTFS

## NTFS

<details>

<summary><strong>Aprende hacking de AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **NTFS**

**NTFS** (**Sistema de Archivos de Nueva Tecnología**) es un sistema de archivos de registro propietario desarrollado por Microsoft.

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
| Mayor a 32,768MB         | 128                 | 64KB         |

### **Espacio de Reserva**

Dado que la unidad de tamaño más pequeña de NTFS es un clúster, cada archivo ocupará varios clústeres completos. Por lo tanto, es altamente probable que **cada archivo ocupe más espacio del necesario**. Estos **espacios no utilizados** reservados por un archivo se llaman **espacio de reserva** y las personas podrían aprovechar esta área para **ocultar información**.

![](<../../../.gitbook/assets/image (498).png>)

### **Sector de Arranque de NTFS**

Cuando formateas un volumen NTFS, el programa de formato asigna los primeros 16 sectores para el archivo de metadatos de arranque. El primer sector es un sector de arranque con un código "bootstrap" y los siguientes 15 sectores son el IPL (Cargador de Programa Inicial) del sector de arranque. Para aumentar la confiabilidad del sistema de archivos, el último sector de una partición NTFS contiene una copia de respaldo del sector de arranque.

### **Tabla Maestra de Archivos (MFT)**

El sistema de archivos NTFS contiene un archivo llamado Tabla Maestra de Archivos (MFT). Existe al menos **una entrada en la MFT para cada archivo en un volumen del sistema de archivos NTFS**, incluida la MFT en sí misma. Toda la información sobre un archivo, incluido su **tamaño, marcas de tiempo de tiempo y fecha, permisos y contenido de datos**, se almacena ya sea en las entradas de la MFT o en el espacio fuera de la MFT que es descrito por las entradas de la MFT.

A medida que se **añaden archivos** a un volumen del sistema de archivos NTFS, se añaden más entradas a la MFT y la **MFT aumenta de tamaño**. Cuando se **eliminan archivos** de un volumen del sistema de archivos NTFS, sus **entradas de MFT se marcan como libres** y pueden ser reutilizadas. Sin embargo, el espacio en disco que se ha asignado para estas entradas no se reasigna, y el tamaño de la MFT no disminuye.

El sistema de archivos NTFS **reserva espacio para la MFT para mantener la MFT lo más contigua posible** a medida que crece. El espacio reservado por el sistema de archivos NTFS para la MFT en cada volumen se llama la **zona de MFT**. El espacio para archivos y directorios también se asigna desde este espacio, pero solo después de que todo el espacio del volumen fuera de la zona de MFT se haya asignado.

Dependiendo del tamaño promedio de los archivos y otras variables, **ya sea la zona de MFT reservada o el espacio no reservado en el disco puede asignarse primero a medida que el disco se llena**. Los volúmenes con un pequeño número de archivos relativamente grandes asignarán primero el espacio no reservado, mientras que los volúmenes con un gran número de archivos relativamente pequeños asignarán primero la zona de MFT. En cualquier caso, la fragmentación de la MFT comienza a ocurrir cuando una región u otra se asigna por completo. Si el espacio no reservado se asigna por completo, el espacio para archivos y directorios de usuario se asignará desde la zona de MFT. Si la zona de MFT se asigna por completo, el espacio para nuevas entradas de MFT se asignará desde el espacio no reservado.

Los sistemas de archivos NTFS también generan un **$MFTMirror**. Esta es una **copia** de los **primeros 4 registros** de la MFT: $MFT, $MFT Mirror, $Log, $Volume.

NTFS reserva los primeros 16 registros de la tabla para información especial:

| Archivo de Sistema     | Nombre de Archivo | Registro MFT | Propósito del Archivo                                                                                                                                                                                                           |
| --------------------- | --------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tabla maestra de archivos     | $Mft      | 0          | Contiene un registro de archivo base para cada archivo y carpeta en un volumen NTFS. Si la información de asignación para un archivo o carpeta es demasiado grande para caber en un solo registro, se asignan otros registros de archivo también.            |
| Tabla maestra de archivos 2   | $MftMirr  | 1          | Una imagen duplicada de los primeros cuatro registros de la MFT. Este archivo garantiza el acceso a la MFT en caso de una falla de un solo sector.                                                                                            |
| Archivo de registro      | $LogFile  | 2          | Contiene una lista de pasos de transacción utilizados para la recuperabilidad de NTFS. El tamaño del archivo de registro depende del tamaño del volumen y puede ser de hasta 4 MB. Es utilizado por Windows NT/2000 para restaurar la consistencia de NTFS después de una falla del sistema. |
| Volumen                | $Volume   | 3          | Contiene información sobre el volumen, como la etiqueta del volumen y la versión del volumen.                                                                                                                                       |
| Definiciones de atributos | $AttrDef  | 4          | Una tabla de nombres de atributos, números y descripciones.                                                                                                                                                                        |
| Índice de nombre de archivo raíz  | $         | 5          | La carpeta raíz.                                                                                                                                                                                                              |
| Mapa de clúster        | $Bitmap   | 6          | Una representación del volumen que muestra qué clústeres están en uso.                                                                                                                                                             |
| Sector de arranque           | $Boot     | 7          | Incluye el BPB utilizado para montar el volumen y código de cargador de arranque adicional utilizado si el volumen es arrancable.                                                                                                                |
| Archivo de clústeres defectuosos      | $BadClus  | 8          | Contiene clústeres defectuosos para el volumen.                                                                                                                                                                                         |
| Archivo de seguridad         | $Secure   | 9          | Contiene descriptores de seguridad únicos para todos los archivos dentro de un volumen.                                                                                                                                                           |
| Tabla de mayúsculas          | $Upcase   | 10         | Convierte caracteres en minúsculas a caracteres en mayúsculas Unicode coincidentes.                                                                                                                                                       |
| Archivo de extensión NTFS   | $Extend   | 11         | Utilizado para varias extensiones opcionales como cuotas, datos de puntos de reanálisis e identificadores de objetos.                                                                                                                              |
|                       |           | 12-15      | Reservado para uso futuro.                                                                                                                                                                                                      |
| Archivo de gestión de cuotas | $Quota    | 24         | Contiene límites de cuota asignados por el usuario en el espacio del volumen.                                                                                                                                                                      |
| Archivo de ID de objeto        | $ObjId    | 25         | Contiene identificadores de objetos de archivo.                                                                                                                                                                                                     |
| Archivo de punto de reanálisis    | $Reparse  | 26         | Este archivo contiene información sobre archivos y carpetas en el volumen, incluidos datos de puntos de reanálisis.                                                                                                                            |

### Cada entrada de la MFT se ve así:

![](<../../../.gitbook/assets/image (499).png>)

Nota cómo cada entrada comienza con "FILE". Cada entrada ocupa 1024 bits. Por lo tanto, después de 1024 bits desde el inicio de una entrada de MFT, encontrarás la siguiente.

Usando el [**Editor de Disco Activo**](https://www.disk-editor.org/index.html) es muy fácil inspeccionar la entrada de un archivo en la MFT. Simplemente haz clic derecho en el archivo y luego haz clic en "Inspeccionar Registro de Archivo"

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

Al verificar la bandera **"En uso"** es muy fácil saber si un archivo fue eliminado (un valor de **0x0 significa eliminado**).

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
| 64              | $OBJECT\_ID              | Un identificador único de 16 bytes para el archivo o directorio. Existe solo en las versiones 3.0+ y posteriores (Windows 2000+).    |
| 80              | $SECURITY\_ DESCRIPTOR   | Las propiedades de control de acceso y seguridad del archivo.                                                           |
| 96              | $VOLUME\_NAME            | Nombre del volumen.                                                                                                      |
| 112             | $VOLUME\_ INFORMATION    | Versión del sistema de archivos y otras banderas.                                                                              |
| 128             | $DATA                    | Contenido del archivo.                                                                                                    |
| 144             | $INDEX\_ROOT             | Nodo raíz de un árbol de índice.                                                                                       |
| 160             | $INDEX\_ALLOCATION       | Nodos de un árbol de índice enraizado en el atributo $INDEX\_ROOT.                                                          |
| 176             | $BITMAP                  | Un mapa de bits para el archivo $MFT y para los índices.                                                                       |
| 192             | $SYMBOLIC\_LINK          | Información de enlace suave. Existe solo en la versión 1.2 (Windows NT).                                                   |
| 192             | $REPARSE\_POINT          | Contiene datos sobre un punto de reanálisis, que se utiliza como un enlace suave en la versión 3.0+ (Windows 2000+).                |
| 208             | $EA\_INFORMATION         | Utilizado para la compatibilidad con aplicaciones OS/2 (HPFS).                                                    |
| 224             | $EA                      | Utilizado para la compatibilidad con aplicaciones OS/2 (HPFS).                                                    |
| 256             | $LOGGED\_UTILITY\_STREAM | Contiene claves e información sobre atributos cifrados en la versión 3.0+ (Windows 2000+).                         |

Por ejemplo, el **tipo 48 (0x30)** identifica el **nombre del archivo**:

![](<../../../.gitbook/assets/image (508).png>)

También es útil entender que **estos atributos pueden ser residentes** (lo que significa que existen dentro de un registro MFT dado) o **no residentes** (lo que significa que existen fuera de un registro MFT dado, en otro lugar en el disco, y simplemente se hacen referencia dentro del registro). Por ejemplo, si el atributo **$Data es residente**, esto significa que **todo el archivo se guarda en la MFT**, si no es residente, entonces el contenido del archivo está en otra parte del sistema de archivos.

Algunos atributos interesantes:

* [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard\_information.html) (entre otros):
* Fecha de creación
* Fecha de modificación
* Fecha de acceso
* Fecha de actualización de MFT
* Permisos de archivo DOS
* [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file\_name.html) (entre otros):
* Nombre del archivo
* Fecha de creación
* Fecha de modificación
* Fecha de acceso
* Fecha de actualización de MFT
* Tamaño asignado
* Tamaño real
* [Referencia de archivo](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html) al directorio padre.
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html) (entre otros):
* Contiene los datos del archivo o la indicación de los sectores donde residen los datos. En el siguiente ejemplo, el atributo de datos no es residente, por lo que el atributo proporciona información sobre los sectores donde residen los datos.

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)

### Marcas de Tiempo de NTFS

![](<../../../.gitbook/assets/image (512).png>)

Otra herramienta útil para analizar la MFT es [**MFT2csv**](https://github.com/jschicht/Mft2Csv) (selecciona el archivo mft o la imagen y presiona dump all y extract para extraer todos los objetos).\
Este programa extraerá todos los datos de la MFT y los presentará en formato CSV. También se puede utilizar para volcar archivos.

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

El archivo **`$LOGFILE`** contiene **registros** sobre las **acciones** que se han **realizado** **en** **archivos**. También **guarda** la **acción** que necesitaría realizar en caso de un **repetir** y la acción necesaria para **volver** al **estado** **anterior**.\
Estos registros son útiles para que la MFT reconstruya el sistema de archivos en caso de que ocurra algún tipo de error. El tamaño máximo de este archivo es de **65536KB**.

Para inspeccionar el `$LOGFILE` necesitas extraerlo e inspeccionar previamente el `$MFT` con [**MFT2csv**](https://github.com/jschicht/Mft2Csv).\
Luego ejecuta [**LogFileParser**](https://github.com/jschicht/LogFileParser) contra este archivo y selecciona el archivo `$LOGFILE` exportado y el CVS de la inspección del `$MFT`. Obtendrás un archivo CSV con los registros de la actividad del sistema de archivos registrados por el log `$LOGFILE`.

![](<../../../.gitbook/assets/image (515).png>)

Filtrando por nombres de archivo puedes ver **todas las acciones realizadas contra un archivo**:

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

El archivo `$EXTEND/$USNJnrl/$J` es un flujo de datos alternativo del archivo `$EXTEND$USNJnrl`. Este artefacto contiene un **registro de cambios producidos dentro del volumen NTFS con más detalle que `$LOGFILE`**.

Para inspe
