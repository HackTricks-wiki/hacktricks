# Artefactos de Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos genéricos de Windows

### Notificaciones de Windows 10

En la ruta `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` puedes encontrar la base de datos `appdb.dat` (antes de Windows anniversary) o `wpndatabase.db` (después de Windows Anniversary).

Dentro de esta base de datos SQLite, puedes encontrar la tabla `Notification` con todas las notificaciones (en formato XML), que pueden contener datos interesantes.

### Timeline

Timeline es una característica de Windows que proporciona un **historial cronológico** de las páginas web visitadas, los documentos editados y las aplicaciones ejecutadas.

La base de datos se encuentra en la ruta `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Esta base de datos se puede abrir con una herramienta SQLite o con la herramienta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **que genera 2 archivos que se pueden abrir con la herramienta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Los archivos descargados pueden contener el **ADS Zone.Identifier**, que indica **cómo** se **descargaron** desde la intranet, internet, etc. Algunos programas (como los navegadores) suelen incluir aún **más** **información**, como la **URL** desde la que se descargó el archivo.

## **Copias de seguridad de archivos**

### Papelera de reciclaje

En Vista/Win7/Win8/Win10, la **Papelera de reciclaje** se encuentra en la carpeta **`$Recycle.bin`**, en la raíz de la unidad (`C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta, se crean 2 archivos específicos:

- `$I{id}`: Información del archivo (fecha en la que se eliminó}
- `$R{id}`: Contenido del archivo

![Copias de seguridad de archivos - Papelera de reciclaje: $R{id}: Contenido del archivo](<../../../images/image (1029).png>)

Con estos archivos puedes utilizar la herramienta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obtener la ubicación original de los archivos eliminados y la fecha en la que se eliminaron (utiliza `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy es una tecnología incluida en Microsoft Windows que puede crear **copias de seguridad** o snapshots de archivos o volúmenes del equipo, incluso cuando están en uso.

Estas copias de seguridad suelen encontrarse en `\System Volume Information`, en la raíz del sistema de archivos, y el nombre está compuesto por **UIDs**, como se muestra en la siguiente imagen:

![Recycle Bin - Volume Shadow Copies: Estas copias de seguridad suelen encontrarse en System Volume Information, en la raíz del sistema de archivos, y el nombre está compuesto por UIDs, como se muestra en la...](<../../../images/image (94).png>)

Al montar la imagen forense con **ArsenalImageMounter**, se puede utilizar la herramienta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) para inspeccionar una shadow copy e incluso **extraer los archivos** de las copias de seguridad de la shadow copy.

![Recycle Bin - Volume Shadow Copies: Al montar la imagen forense con ArsenalImageMounter, se puede utilizar la herramienta ShadowCopyView para inspeccionar una shadow copy e incluso extraer los archivos...](<../../../images/image (576).png>)

La entrada del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene los archivos y las claves **que no se deben incluir en la copia de seguridad**:

![Recycle Bin - Volume Shadow Copies: La entrada del registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contiene los archivos y las claves que no se deben incluir en la copia de seguridad](<../../../images/image (254).png>)

El registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene información de configuración sobre las `Volume Shadow Copies`.

### Archivos guardados automáticamente de Office

Puedes encontrar los archivos guardados automáticamente de Office en: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Un shell item es un elemento que contiene información sobre cómo acceder a otro archivo.

### Documentos recientes (LNK)

Windows **crea** **automáticamente** estos **accesos directos** cuando el usuario **abre, utiliza o crea un archivo** en:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Cuando se crea una carpeta, también se crea un enlace a la carpeta, a la carpeta principal y a la carpeta principal de esta.

Estos archivos de enlace creados automáticamente **contienen información sobre el origen**, como si es un **archivo** **o** una **carpeta**, las **horas** **MAC** de ese archivo, la **información del volumen** donde está almacenado el archivo y la **carpeta del archivo de destino**. Esta información puede ser útil para recuperar esos archivos en caso de que se hayan eliminado.

Además, la **fecha de creación del archivo de enlace** corresponde a la primera **vez** que se **utilizó** el archivo original, y la **fecha** de **modificación** del archivo de enlace corresponde a la última **vez** que se utilizó el archivo de origen.

Para inspeccionar estos archivos puedes utilizar [**LinkParser**](http://4discovery.com/our-tools/).

En esta herramienta encontrarás **2 conjuntos** de marcas de tiempo:

- **Primer conjunto:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Segundo conjunto:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

El primer conjunto de marcas de tiempo hace referencia a las **marcas de tiempo del propio archivo**. El segundo conjunto hace referencia a las **marcas de tiempo del archivo enlazado**.

Puedes obtener la misma información ejecutando la herramienta CLI de Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
En este caso, la información se va a guardar dentro de un archivo CSV.

### Jumplists

Estos son los archivos recientes que se indican por aplicación. Es la lista de **archivos recientes utilizados por una aplicación** a la que puedes acceder desde cada aplicación. Pueden crearse **automáticamente o de forma personalizada**.

Los **jumplists** creados automáticamente se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Los jumplists reciben nombres siguiendo el formato `{id}.autmaticDestinations-ms`, donde el ID inicial es el ID de la aplicación.

Los jumplists personalizados se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` y normalmente los crea la aplicación porque algo **importante** ha ocurrido con el archivo (quizás se haya marcado como favorito).

La **hora de creación** de cualquier jumplist indica **la primera vez que se accedió al archivo** y la **hora de modificación, la última vez**.

Puedes inspeccionar los jumplists utilizando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Recent Documents (LNK) - Jumplists: You can inspect the jumplists using JumplistExplorer](<../../../images/image (168).png>)

(_Ten en cuenta que las marcas de tiempo proporcionadas por JumplistExplorer están relacionadas con el propio archivo jumplist_)

### Shellbags

[**Sigue este enlace para aprender qué son los shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de dispositivos USB en Windows

Es posible identificar que se utilizó un dispositivo USB gracias a la creación de:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Ten en cuenta que algunos archivos LNK, en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE:

![Shellbags - Use of Windows USBs: Note that some LNK file instead of pointing to the original path, points to the WPDNSE folder](<../../../images/image (218).png>)

Los archivos de la carpeta WPDNSE son una copia de los originales, por lo que no sobrevivirán a un reinicio del PC, y el GUID se obtiene de un shellbag.

### Información del Registry

[Consulta esta página para aprender](interesting-windows-registry-keys.md#usb-information) qué claves del Registry contienen información interesante sobre los dispositivos USB conectados.

### setupapi

Comprueba el archivo `C:\Windows\inf\setupapi.dev.log` para obtener las marcas de tiempo de cuándo se produjo la conexión USB (busca `Section start`).

![Registry Information - setupapi: Check the file C: Windows inf setupapi.dev.log to get the timestamps about when the USB connection was produced (search for Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) puede utilizarse para obtener información sobre los dispositivos USB que se han conectado a una imagen.

![setupapi - USB Detective: USBDetective can be used to obtain information about the USB devices that have been connected to an image](<../../../images/image (452).png>)

### Plug and Play Cleanup

La tarea programada conocida como 'Plug and Play Cleanup' está diseñada principalmente para eliminar versiones obsoletas de controladores. A diferencia de su propósito especificado de conservar la versión más reciente del paquete de controladores, fuentes online sugieren que también busca controladores que hayan estado inactivos durante 30 días. En consecuencia, los controladores de dispositivos extraíbles que no se hayan conectado en los últimos 30 días podrían eliminarse.<sup>[[1]](#references)</sup>

La tarea se encuentra en la siguiente ruta: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Se proporciona una captura de pantalla que muestra el contenido de la tarea: ![USB Detective - Plug and Play Cleanup: The task is located at the following path: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes y configuraciones clave de la tarea:**

- **pnpclean.dll**: Esta DLL es responsable del proceso de limpieza real.
- **UseUnifiedSchedulingEngine**: Establecido en `TRUE`, lo que indica el uso del motor genérico de programación de tareas.
- **MaintenanceSettings**:
- **Period ('P1M')**: Indica al Task Scheduler que inicie la tarea de limpieza mensualmente durante el mantenimiento Automatic habitual.
- **Deadline ('P2M')**: Indica al Task Scheduler que, si la tarea falla durante dos meses consecutivos, la ejecute durante el mantenimiento Automatic de emergencia.

Esta configuración garantiza el mantenimiento y la limpieza periódicos de los controladores, con disposiciones para volver a intentar la tarea en caso de fallos consecutivos.

**Para obtener más información, consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Los emails contienen **2 partes interesantes: los headers y el contenido** del email. En los **headers** puedes encontrar información como:

- **Quién** envió los emails (dirección de email, IP y mail servers que han redirigido el email)
- **Cuándo** se envió el email

Además, dentro de los headers `References` y `In-Reply-To` puedes encontrar el ID de los mensajes:

![Plug and Play Cleanup - Emails: When was the email sent](<../../../images/image (593).png>)

### Windows Mail App

Esta aplicación guarda los emails en HTML o texto. Puedes encontrar los emails dentro de subcarpetas de `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Los emails se guardan con la extensión `.dat`.

Los **metadatos** de los emails y los **contactos** se pueden encontrar dentro de la **base de datos EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia la extensión** del archivo de `.vol` a `.edb` y podrás utilizar la herramienta [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) para abrirlo. Dentro de la tabla `Message` puedes ver los emails.

### Microsoft Outlook

Cuando se utilizan Exchange servers o clientes Outlook, habrá algunos headers MAPI:

- `Mapi-Client-Submit-Time`: Hora del sistema en la que se envió el email.
- `Mapi-Conversation-Index`: Número de mensajes hijos del thread y marca de tiempo de cada mensaje del thread.
- `Mapi-Entry-ID`: Identificador del mensaje.
- `Mappi-Message-Flags` y `Pr_last_Verb-Executed`: Información sobre el cliente MAPI (¿mensaje leído?, ¿no leído?, ¿respondido?, ¿redirigido?, ¿fuera de la oficina?)

En el cliente Microsoft Outlook, todos los mensajes enviados/recibidos, los datos de los contactos y los datos del calendario se almacenan en un archivo PST en:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

La ruta del Registry `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica el archivo que se está utilizando.

Puedes abrir el archivo PST utilizando la herramienta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: You can open the PST file using the tool Kernel PST Viewer](<../../../images/image (498).png>)

### Archivos OST de Microsoft Outlook

Un **archivo OST** es generado por Microsoft Outlook cuando está configurado con un servidor **IMAP** o **Exchange**, y almacena información similar a la de un archivo PST. Este archivo se sincroniza con el servidor, conservando los datos de **los últimos 12 meses** hasta un **tamaño máximo de 50 GB**, y se encuentra en el mismo directorio que el archivo PST. Para visualizar un archivo OST, puede utilizarse [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recuperación de Attachments

Los attachments perdidos podrían recuperarse desde:

- Para **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Para **IE11 y superiores**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Archivos MBOX de Thunderbird

**Thunderbird** utiliza **archivos MBOX** para almacenar datos, ubicados en `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturas de imágenes

- **Windows XP y 8-8.1**: Acceder a una carpeta con miniaturas genera un archivo `thumbs.db` que almacena vistas previas de imágenes, incluso después de eliminarlas.
- **Windows 7/10**: `thumbs.db` se crea cuando se accede a través de una red mediante una ruta UNC.
- **Windows Vista y versiones posteriores**: Las vistas previas de miniaturas se centralizan en `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, con archivos denominados **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) y [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) son herramientas para visualizar estos archivos.

### Información del Windows Registry

El Windows Registry, que almacena una gran cantidad de datos sobre la actividad del sistema y del usuario, se encuentra dentro de archivos en:

- `%windir%\System32\Config` para varias subclaves de `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` para `HKEY_CURRENT_USER`.
- Windows Vista y versiones posteriores realizan copias de seguridad de los archivos del Registry de `HKEY_LOCAL_MACHINE` en `%Windir%\System32\Config\RegBack\`.
- Además, la información sobre la ejecución de programas se almacena en `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` desde Windows Vista y Windows 2008 Server en adelante.

### Herramientas

Algunas herramientas son útiles para analizar los archivos del Registry:

- **Registry Editor**: Está instalado en Windows. Es una GUI para navegar por el Windows Registry de la sesión actual.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite cargar el archivo del Registry y navegar por él mediante una GUI. También contiene Bookmarks que resaltan claves con información interesante.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): También cuenta con una GUI que permite navegar por el Registry cargado y contiene plugins que resaltan información interesante dentro del Registry cargado.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Otra aplicación GUI capaz de extraer la información importante del Registry cargado.

### Recuperación de elementos eliminados

Cuando se elimina una clave, se marca como tal, pero no se elimina hasta que se necesita el espacio que ocupa. Por lo tanto, utilizando herramientas como **Registry Explorer**, es posible recuperar estas claves eliminadas.

### Last Write Time

Cada Key-Value contiene una **marca de tiempo** que indica la última vez que se modificó.

### SAM

El archivo/hive **SAM** contiene los hashes de las **contraseñas de los usuarios, grupos y usuarios** del sistema.

En `SAM\Domains\Account\Users` puedes obtener el nombre de usuario, el RID, el último inicio de sesión, el último inicio de sesión fallido, el contador de inicios de sesión, la política de contraseñas y cuándo se creó la cuenta. Para obtener los **hashes** también **necesitas** el archivo/hive **SYSTEM**.

### Entradas interesantes en el Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programas ejecutados

### Procesos básicos de Windows

En [esta publicación](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) puedes aprender sobre los procesos comunes de Windows para detectar comportamientos sospechosos.

### Aplicaciones recientes de Windows

Dentro del Registry `NTUSER.DAT`, en la ruta `Software\Microsoft\Current Version\Search\RecentApps`, puedes encontrar subclaves con información sobre la **aplicación ejecutada**, la **última vez** que se ejecutó y el **número de veces** que se inició.

### BAM (Background Activity Moderator)

Puedes abrir el archivo `SYSTEM` con un editor del Registry y, dentro de la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, encontrar la información sobre las **aplicaciones ejecutadas por cada usuario** (observa el `{SID}` en la ruta) y **a qué hora** se ejecutaron (la hora está dentro del valor Data del Registry).

### Windows Prefetch

Prefetching es una técnica que permite a un equipo **obtener silenciosamente los recursos necesarios para mostrar contenido** al que un usuario **podría acceder en un futuro cercano**, de modo que los recursos puedan consultarse más rápidamente.

Windows prefetch consiste en crear **caches de los programas ejecutados** para poder cargarlos más rápido. Estos caches se crean como archivos `.pf` dentro de la ruta `C:\Windows\Prefetch`. Hay un límite de 128 archivos en XP/VISTA/WIN7 y de 1024 archivos en Win8/Win10.

El nombre del archivo se crea como `{program_name}-{hash}.pf` (el hash se basa en la ruta y los argumentos del ejecutable). En W10 estos archivos están comprimidos. Ten en cuenta que la mera presencia del archivo indica que **el programa se ejecutó** en algún momento.

El archivo `C:\Windows\Prefetch\Layout.ini` contiene los **nombres de las carpetas de los archivos que se prefetch**. Este archivo contiene **información sobre el número de ejecuciones**, las **fechas** de ejecución y los **archivos** **abiertos** por el programa.

Para inspeccionar estos archivos puedes utilizar la herramienta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** tiene el mismo objetivo que prefetch: **cargar los programas más rápido** prediciendo qué se cargará a continuación. Sin embargo, no sustituye al servicio de prefetch.\
Este servicio genera archivos de base de datos en `C:\Windows\Prefetch\Ag*.db`.

En estas bases de datos puedes encontrar el **nombre** del **programa**, el **número de ejecuciones**, los **archivos** **abiertos**, el **volumen** **accedido**, la **ruta** **completa**, los **intervalos de tiempo** y las **marcas de tiempo**.

Puedes acceder a esta información usando la herramienta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **supervisa** los **recursos** **consumidos** **por un proceso**. Apareció en W8 y almacena los datos en una base de datos ESE ubicada en `C:\Windows\System32\sru\SRUDB.dat`.

Proporciona la siguiente información:

- ID de la aplicación y ruta
- Usuario que ejecutó el proceso
- Bytes enviados
- Bytes recibidos
- Interfaz de red
- Duración de la conexión
- Duración del proceso

Esta información se actualiza cada 60 minutos.

Puedes obtener la fecha de este archivo usando la herramienta [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

La **AppCompatCache**, también conocida como **ShimCache**, forma parte de la **Application Compatibility Database** desarrollada por **Microsoft** para abordar problemas de compatibilidad de aplicaciones. Este componente del sistema registra varios datos de metadatos de los archivos, entre ellos:

- Ruta completa del archivo
- Tamaño del archivo
- Hora de última modificación en **$Standard_Information** (SI)
- Hora de última actualización de la ShimCache
- Indicador de ejecución del proceso

Estos datos se almacenan en el registro en ubicaciones específicas según la versión del sistema operativo:

- En XP, los datos se almacenan en `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, con una capacidad de 96 entradas.
- En Server 2003, así como en las versiones 2008, 2012, 2016, 7, 8 y 10 de Windows, la ruta de almacenamiento es `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`, con una capacidad de 512 y 1024 entradas, respectivamente.

Para analizar la información almacenada, se recomienda utilizar la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Para analizar la información almacenada, se recomienda utilizar la herramienta AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

El archivo **Amcache.hve** es esencialmente una registry hive que registra detalles sobre las aplicaciones que se han ejecutado en un sistema. Normalmente se encuentra en `C:\Windows\AppCompat\Programas\Amcache.hve`.

Este archivo destaca por almacenar registros de procesos ejecutados recientemente, incluidas las rutas de los archivos ejecutables y sus hashes SHA1. Esta información es muy valiosa para rastrear la actividad de las aplicaciones en un sistema.

Para extraer y analizar los datos de **Amcache.hve**, se puede utilizar la herramienta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). El siguiente comando es un ejemplo de cómo utilizar AmcacheParser para analizar el contenido del archivo **Amcache.hve** y mostrar los resultados en formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre los archivos CSV generados, `Amcache_Unassociated file entries` es especialmente destacable debido a la gran cantidad de información que proporciona sobre las entradas de archivos no asociadas.

El archivo CVS generado más interesante es `Amcache_Unassociated file entries`.

### RecentFileCache

Este artefacto solo se puede encontrar en W7, en `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, y contiene información sobre la ejecución reciente de algunos binarios.

Puedes utilizar la herramienta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analizar el archivo.

### Scheduled tasks

Puedes extraerlas de `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` y leerlas como XML.

### Services

Puedes encontrarlos en el registro, en `SYSTEM\ControlSet001\Services`. Puedes ver qué se va a ejecutar y cuándo.

### **Windows Store**

Las aplicaciones instaladas se pueden encontrar en `\ProgramData\Microsoft\Windows\AppRepository\`\
Este repositorio contiene un **log** con **cada aplicación instalada** en el sistema dentro de la base de datos **`StateRepository-Machine.srd`**.

Dentro de la tabla Application de esta base de datos, es posible encontrar las columnas: "Application ID", "PackageNumber" y "Display Name". Estas columnas contienen información sobre las aplicaciones preinstaladas e instaladas, y permiten determinar si algunas aplicaciones fueron desinstaladas, ya que los IDs de las aplicaciones instaladas deberían ser secuenciales.

También es posible **encontrar aplicaciones instaladas** en la ruta del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Y las **aplicaciones** **desinstaladas** en: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

La información que aparece dentro de los eventos de Windows es:

- Qué ocurrió
- Marca de tiempo (UTC + 0)
- Usuarios involucrados
- Hosts involucrados (hostname, IP)
- Activos accedidos (archivos, carpetas, impresoras, servicios)

Los logs se encuentran en `C:\Windows\System32\config` antes de Windows Vista y en `C:\Windows\System32\winevt\Logs` después de Windows Vista. Antes de Windows Vista, los logs de eventos estaban en formato binario y, después, están en **formato XML** y utilizan la extensión **.evtx**.

La ubicación de los archivos de eventos se puede encontrar en el registro SYSTEM, en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Se pueden visualizar desde el Windows Event Viewer (**`eventvwr.msc`**) o con otras herramientas como [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Understanding Windows Security Event Logging

Los eventos de acceso se registran en el archivo de configuración de seguridad ubicado en `C:\Windows\System32\winevt\Security.evtx`. El tamaño de este archivo se puede ajustar y, cuando se alcanza su capacidad, los eventos antiguos se sobrescriben. Los eventos registrados incluyen inicios y cierres de sesión de usuarios, acciones de los usuarios y cambios en la configuración de seguridad, así como el acceso a archivos, carpetas y activos compartidos.

### Key Event IDs for User Authentication:

- **EventID 4624**: Indica que un usuario se autenticó correctamente.
- **EventID 4625**: Indica un fallo de autenticación.
- **EventIDs 4634/4647**: Representan eventos de cierre de sesión de usuarios.
- **EventID 4672**: Indica un inicio de sesión con privilegios administrativos.

#### Sub-types within EventID 4634/4647:

- **Interactive (2)**: Inicio de sesión directo del usuario.
- **Network (3)**: Acceso a carpetas compartidas.
- **Batch (4)**: Ejecución de procesos por lotes.
- **Service (5)**: Inicio de servicios.
- **Proxy (6)**: Autenticación mediante proxy.
- **Unlock (7)**: Pantalla desbloqueada con una contraseña.
- **Network Cleartext (8)**: Transmisión de contraseñas en texto claro, a menudo desde IIS.
- **New Credentials (9)**: Uso de credenciales diferentes para acceder.
- **Remote Interactive (10)**: Inicio de sesión mediante escritorio remoto o servicios de terminal.
- **Cache Interactive (11)**: Inicio de sesión con credenciales almacenadas en caché, sin contacto con el controlador de dominio.
- **Cache Remote Interactive (12)**: Inicio de sesión remoto con credenciales almacenadas en caché.
- **Cached Unlock (13)**: Desbloqueo con credenciales almacenadas en caché.

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: El nombre de usuario no existe; podría indicar un ataque de enumeración de nombres de usuario.
- **0xC000006A**: Nombre de usuario correcto, pero contraseña incorrecta; posible intento de adivinación de contraseñas o brute-force.
- **0xC0000234**: Cuenta de usuario bloqueada; puede producirse después de un ataque de brute-force que provoque múltiples inicios de sesión fallidos.
- **0xC0000072**: Cuenta deshabilitada; intentos no autorizados de acceder a cuentas deshabilitadas.
- **0xC000006F**: Inicio de sesión fuera del horario permitido; indica intentos de acceso fuera del horario establecido, una posible señal de acceso no autorizado.
- **0xC0000070**: Incumplimiento de las restricciones de la workstation; podría ser un intento de iniciar sesión desde una ubicación no autorizada.
- **0xC0000193**: Cuenta caducada; intentos de acceso con cuentas de usuario caducadas.
- **0xC0000071**: Contraseña caducada; intentos de inicio de sesión con contraseñas obsoletas.
- **0xC0000133**: Problemas de sincronización horaria; grandes discrepancias de tiempo entre el cliente y el servidor pueden indicar ataques más sofisticados, como pass-the-ticket.
- **0xC0000224**: Se requiere un cambio obligatorio de contraseña; los cambios obligatorios frecuentes podrían sugerir un intento de desestabilizar la seguridad de la cuenta.
- **0xC0000225**: Indica un bug del sistema en lugar de un problema de seguridad.
- **0xC000015b**: Tipo de inicio de sesión denegado; intento de acceso con un tipo de inicio de sesión no autorizado, como un usuario que intenta ejecutar un inicio de sesión de servicio.

#### EventID 4616:

- **Time Change**: Modificación de la hora del sistema, lo que podría ocultar la línea temporal de los eventos.

#### EventID 6005 and 6006:

- **System Startup and Shutdown**: EventID 6005 indica el inicio del sistema, mientras que EventID 6006 indica su apagado.

#### EventID 1102:

- **Log Deletion**: Borrado de logs de seguridad, lo que suele ser una señal de alerta de encubrimiento de actividades ilícitas.

#### EventIDs for USB Device Tracking:

- **20001 / 20003 / 10000**: Primera conexión del dispositivo USB.
- **10100**: Actualización del controlador USB.
- **EventID 112**: Momento de inserción del dispositivo USB.

Para consultar ejemplos prácticos sobre la simulación de estos tipos de inicio de sesión y las oportunidades de credential dumping, consulta la guía detallada de [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Los detalles de los eventos, incluidos los códigos de estado y subestado, proporcionan más información sobre las causas de los eventos, especialmente en el Event ID 4625.

### Recovering Windows Events

Para aumentar las posibilidades de recuperar Windows Events eliminados, es recomendable apagar el ordenador sospechoso desenchufándolo directamente. Se recomienda **Bulk_extractor**, una herramienta de recuperación a la que se debe especificar la extensión `.evtx`, para intentar recuperar estos eventos.

### Identifying Common Attacks via Windows Events

Para obtener una guía completa sobre el uso de Windows Event IDs para identificar cyber attacks comunes, visita [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Se identifican mediante múltiples registros EventID 4625, seguidos de un EventID 4624 si el ataque tiene éxito.

#### Time Change

Registrados por EventID 4616, los cambios en la hora del sistema pueden complicar el análisis forense.

#### USB Device Tracking

Entre los System EventIDs útiles para el seguimiento de dispositivos USB se incluyen 20001/20003/10000 para el uso inicial, 10100 para las actualizaciones de controladores y EventID 112 de DeviceSetupManager para las marcas de tiempo de inserción.

#### System Power Events

EventID 6005 indica el inicio del sistema, mientras que EventID 6006 indica el apagado.

#### Log Deletion

El Security EventID 1102 indica el borrado de logs, un evento crítico para el análisis forense.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
