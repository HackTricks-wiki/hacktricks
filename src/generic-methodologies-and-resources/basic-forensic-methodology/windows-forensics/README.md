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

Los archivos descargados pueden contener el **ADS Zone.Identifier**, que indica **cómo** se **descargaron** desde la intranet, internet, etc. Algunos programas (como los navegadores) suelen incluir incluso **más** **información**, como la **URL** desde la que se descargó el archivo.

## **Copias de seguridad de archivos**

### Papelera de reciclaje

En Vista/Win7/Win8/Win10, la **Papelera de reciclaje** se puede encontrar en la carpeta **`$Recycle.bin`**, en la raíz de la unidad (`C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta, se crean 2 archivos específicos:

- `$I{id}`: Información del archivo (fecha en la que se eliminó}
- `$R{id}`: Contenido del archivo

![Copias de seguridad de archivos - Papelera de reciclaje: $R{id}: Contenido del archivo](<../../../images/image (1029).png>)

Con estos archivos puedes utilizar la herramienta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obtener la ubicación original de los archivos eliminados y la fecha en la que se eliminaron (utiliza `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Copias de archivos - Papelera de reciclaje: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy es una tecnología incluida en Microsoft Windows que puede crear **copias de seguridad** o snapshots de archivos o volúmenes del equipo, incluso cuando están en uso.

Estas copias de seguridad normalmente se encuentran en `\System Volume Information`, en la raíz del sistema de archivos, y el nombre está compuesto por **UIDs**, como se muestra en la siguiente imagen:

![Papelera de reciclaje - Volume Shadow Copies: Estas copias de seguridad normalmente se encuentran en System Volume Information, en la raíz del sistema de archivos, y el nombre está compuesto por UIDs, como se muestra en la...](<../../../images/image (94).png>)

Al montar la imagen forense con **ArsenalImageMounter**, se puede utilizar la herramienta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) para inspeccionar una shadow copy e incluso **extraer los archivos** de las copias de seguridad de la shadow copy.

![Papelera de reciclaje - Volume Shadow Copies: Al montar la imagen forense con ArsenalImageMounter, se puede utilizar la herramienta ShadowCopyView para inspeccionar una shadow copy e incluso extraer los archivos...](<../../../images/image (576).png>)

La entrada del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene los archivos y las claves **que no se deben incluir en la copia de seguridad**:

![Papelera de reciclaje - Volume Shadow Copies: La entrada del registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contiene los archivos y las claves que no se deben incluir en la copia de seguridad](<../../../images/image (254).png>)

El registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene información de configuración sobre `Volume Shadow Copies`.

### Archivos guardados automáticamente de Office

Puedes encontrar los archivos guardados automáticamente de Office en: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementos de Shell

Un elemento de shell es un elemento que contiene información sobre cómo acceder a otro archivo.

### Documentos recientes (LNK)

Windows **crea** **automáticamente** estos **accesos directos** cuando el usuario **abre, utiliza o crea un archivo** en:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Cuando se crea una carpeta, también se crea un enlace a la carpeta, a la carpeta principal y a la carpeta principal de esta última.

Estos archivos de enlace creados automáticamente **contienen información sobre el origen**, como si es un **archivo** **o** una **carpeta**, las **marcas de tiempo** **MAC** de ese archivo, la **información del volumen** donde está almacenado el archivo y la **carpeta del archivo de destino**. Esta información puede ser útil para recuperar esos archivos en caso de que se hayan eliminado.

Además, la **fecha de creación del enlace** es la primera **hora** en que el archivo original se **utilizó** por **primera** vez, y la **fecha** de **modificación** del archivo de enlace es la última **hora** en que se utilizó el archivo de origen.

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

Los **jumplists** creados automáticamente se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Los jumplists se nombran siguiendo el formato `{id}.autmaticDestinations-ms`, donde el ID inicial es el ID de la aplicación.

Los jumplists personalizados se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` y normalmente los crea la aplicación porque ha ocurrido algo **importante** con el archivo (quizá se haya marcado como favorito).

La **hora de creación** de cualquier jumplist indica **la primera vez que se accedió al archivo**, y la **hora de modificación, la última vez**.

Puedes inspeccionar los jumplists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Documentos recientes (LNK) - Jumplists: Puedes inspeccionar los jumplists usando JumplistExplorer](<../../../images/image (168).png>)

(_Ten en cuenta que las marcas de tiempo proporcionadas por JumplistExplorer están relacionadas con el propio archivo del jumplist_)

### Shellbags

[**Sigue este enlace para saber qué son los shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de dispositivos USB en Windows

Es posible identificar que se utilizó un dispositivo USB gracias a la creación de:

- Carpeta Recent de Windows
- Carpeta Recent de Microsoft Office
- Jumplists

Ten en cuenta que algunos archivos LNK, en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE:

![Shellbags - Uso de dispositivos USB en Windows: Ten en cuenta que algunos archivos LNK, en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE](<../../../images/image (218).png>)

Los archivos de la carpeta WPDNSE son una copia de los originales, por lo que no sobrevivirán a un reinicio del PC, y el GUID se obtiene de un shellbag.

### Información del Registry

[Consulta esta página para saber](interesting-windows-registry-keys.md#usb-information) qué claves del Registry contienen información interesante sobre los dispositivos USB conectados.

### setupapi

Comprueba el archivo `C:\Windows\inf\setupapi.dev.log` para obtener las marcas de tiempo de cuándo se produjo la conexión USB (busca `Section start`).

![Información del Registry - setupapi: Comprueba el archivo C: Windows inf setupapi.dev.log para obtener las marcas de tiempo de cuándo se produjo la conexión USB (busca Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) puede utilizarse para obtener información sobre los dispositivos USB que se han conectado a una imagen.

![setupapi - USB Detective: USBDetective puede utilizarse para obtener información sobre los dispositivos USB que se han conectado a una imagen](<../../../images/image (452).png>)

### Plug and Play Cleanup

La tarea programada conocida como 'Plug and Play Cleanup' está diseñada principalmente para eliminar versiones de controladores obsoletas. Contrariamente a su propósito especificado de conservar la versión más reciente del paquete de controladores, fuentes online sugieren que también busca controladores que hayan estado inactivos durante 30 días. En consecuencia, los controladores de dispositivos extraíbles que no se hayan conectado en los últimos 30 días pueden ser eliminados.<sup>[[1]](#references)</sup>

La tarea se encuentra en la siguiente ruta: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Se proporciona una captura de pantalla que muestra el contenido de la tarea: ![USB Detective - Plug and Play Cleanup: La tarea se encuentra en la siguiente ruta: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes y configuración clave de la tarea:**

- **pnpclean.dll**: Esta DLL es responsable del proceso de limpieza real.
- **UseUnifiedSchedulingEngine**: Establecido en `TRUE`, indica el uso del motor genérico de programación de tareas.
- **MaintenanceSettings**:
- **Period ('P1M')**: Indica al Task Scheduler que inicie mensualmente la tarea de limpieza durante el mantenimiento Automatic normal.
- **Deadline ('P2M')**: Indica al Task Scheduler que, si la tarea falla durante dos meses consecutivos, ejecute la tarea durante el mantenimiento Automatic de emergencia.

Esta configuración garantiza el mantenimiento y la limpieza periódicos de los controladores, con disposiciones para volver a intentar la tarea en caso de fallos consecutivos.

**Para obtener más información, consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Los emails contienen **2 partes interesantes: los headers y el contenido** del email. En los **headers** puedes encontrar información como:

- **Quién** envió los emails (dirección de email, IP, mail servers que han redirigido el email)
- **Cuándo** se envió el email

Además, dentro de los headers `References` y `In-Reply-To` puedes encontrar el ID de los mensajes:

![Plug and Play Cleanup - Emails: Cuándo se envió el email](<../../../images/image (593).png>)

### Windows Mail App

Esta aplicación guarda los emails en HTML o texto. Puedes encontrar los emails dentro de subcarpetas de `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Los emails se guardan con la extensión `.dat`.

Los **metadatos** de los emails y los **contactos** pueden encontrarse dentro de la **base de datos EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia la extensión** del archivo de `.vol` a `.edb` y podrás utilizar la herramienta [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) para abrirlo. Dentro de la tabla `Message` puedes ver los emails.

### Microsoft Outlook

Cuando se utilizan Exchange servers o clientes Outlook, habrá algunos headers MAPI:

- `Mapi-Client-Submit-Time`: Hora del sistema en la que se envió el email
- `Mapi-Conversation-Index`: Número de mensajes secundarios del thread y timestamp de cada mensaje del thread
- `Mapi-Entry-ID`: Identificador del mensaje.
- `Mappi-Message-Flags` y `Pr_last_Verb-Executed`: Información sobre el cliente MAPI (¿mensaje leído? ¿no leído? ¿respondido? ¿redirigido? ¿fuera de la oficina?)

En el cliente Microsoft Outlook, todos los mensajes enviados/recibidos, los datos de los contactos y los datos del calendario se almacenan en un archivo PST en:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

La ruta del Registry `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica el archivo que se está utilizando.

Puedes abrir el archivo PST usando la herramienta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: Puedes abrir el archivo PST usando la herramienta Kernel PST Viewer](<../../../images/image (498).png>)

### Archivos OST de Microsoft Outlook

Un **archivo OST** es generado por Microsoft Outlook cuando está configurado con **IMAP** o un servidor **Exchange**, y almacena información similar a la de un archivo PST. Este archivo se sincroniza con el servidor, conservando los datos de **los últimos 12 meses** hasta un **tamaño máximo de 50 GB**, y se encuentra en el mismo directorio que el archivo PST. Para visualizar un archivo OST, se puede utilizar [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recuperación de adjuntos

Los adjuntos perdidos podrían recuperarse de:

- Para **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Para **IE11 y posteriores**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Archivos MBOX de Thunderbird

**Thunderbird** utiliza **archivos MBOX** para almacenar datos, ubicados en `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturas de imágenes

- **Windows XP y 8-8.1**: Acceder a una carpeta con miniaturas genera un archivo `thumbs.db` que almacena vistas previas de imágenes, incluso después de eliminarlas.
- **Windows 7/10**: `thumbs.db` se crea cuando se accede a través de una red mediante una ruta UNC.
- **Windows Vista y versiones posteriores**: Las vistas previas de miniaturas se centralizan en `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, con archivos denominados **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) y [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) son herramientas para visualizar estos archivos.

### Información del Windows Registry

El Windows Registry, que almacena gran cantidad de datos sobre la actividad del sistema y del usuario, se encuentra en archivos ubicados en:

- `%windir%\System32\Config` para varias subclaves de `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` para `HKEY_CURRENT_USER`.
- Windows Vista y versiones posteriores realizan copias de seguridad de los archivos del Registry de `HKEY_LOCAL_MACHINE` en `%Windir%\System32\Config\RegBack\`.
- Además, la información sobre la ejecución de programas se almacena en `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` desde Windows Vista y Windows 2008 Server en adelante.

### Tools

Algunas herramientas son útiles para analizar los archivos del Registry:

- **Registry Editor**: Está instalado en Windows. Es una GUI para navegar por el Registry de Windows de la sesión actual.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite cargar el archivo del Registry y navegar por él mediante una GUI. También contiene Bookmarks que destacan claves con información interesante.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): De nuevo, cuenta con una GUI que permite navegar por el Registry cargado y también contiene plugins que destacan información interesante dentro del Registry cargado.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Otra aplicación GUI capaz de extraer la información importante del Registry cargado.

### Recuperación de elementos eliminados

Cuando se elimina una clave, queda marcada como tal, pero no se eliminará hasta que se necesite el espacio que ocupa. Por lo tanto, utilizando herramientas como **Registry Explorer**, es posible recuperar estas claves eliminadas.

### Last Write Time

Cada Key-Value contiene un **timestamp** que indica la última vez que se modificó.

### SAM

El archivo/hive **SAM** contiene los hashes de las **contraseñas de los usuarios, grupos y usuarios** del sistema.

En `SAM\Domains\Account\Users` puedes obtener el nombre de usuario, el RID, el último inicio de sesión, el último inicio de sesión fallido, el contador de inicios de sesión, la política de contraseñas y cuándo se creó la cuenta. Para obtener los **hashes** también **necesitas** el archivo/hive **SYSTEM**.

### Entradas interesantes en el Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programas ejecutados

### Procesos básicos de Windows

En [esta publicación](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) puedes aprender sobre los procesos comunes de Windows para detectar comportamientos sospechosos.<sup>[[2]](#references)</sup>

### Aplicaciones recientes de Windows

Dentro del Registry `NTUSER.DAT`, en la ruta `Software\Microsoft\Current Version\Search\RecentApps`, puedes encontrar subclaves con información sobre la **aplicación ejecutada**, la **última vez** que se ejecutó y el **número de veces** que se inició.

### BAM (Background Activity Moderator)

Puedes abrir el archivo `SYSTEM` con un editor del Registry y, dentro de la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, encontrar la información sobre las **aplicaciones ejecutadas por cada usuario** (observa el `{SID}` en la ruta) y **a qué hora** se ejecutaron (la hora está dentro del valor Data del Registry).

### Windows Prefetch

Prefetching es una técnica que permite a un ordenador **obtener de forma silenciosa los recursos necesarios para mostrar contenido** al que un usuario **podría acceder próximamente**, de modo que los recursos puedan utilizarse más rápidamente.

Windows prefetch consiste en crear **caches de los programas ejecutados** para poder cargarlos más rápido. Estas caches se crean como archivos `.pf` dentro de la ruta: `C:\Windows\Prefetch`. Existe un límite de 128 archivos en XP/VISTA/WIN7 y de 1024 archivos en Win8/Win10.

El nombre del archivo se crea como `{program_name}-{hash}.pf` (el hash se basa en la ruta y los argumentos del ejecutable). En W10 estos archivos están comprimidos. Ten en cuenta que la mera presencia del archivo indica que **el programa se ejecutó** en algún momento.

El archivo `C:\Windows\Prefetch\Layout.ini` contiene los **nombres de las carpetas de los archivos que se precargan**. Este archivo contiene **información sobre el número de ejecuciones**, las **fechas** de ejecución y los **archivos** **abiertos** por el programa.

Para inspeccionar estos archivos puedes utilizar la herramienta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** tiene el mismo objetivo que prefetch, **cargar los programas más rápido** prediciendo lo que se cargará a continuación. Sin embargo, no sustituye al servicio de prefetch.\
Este servicio generará archivos de base de datos en `C:\Windows\Prefetch\Ag*.db`.

En estas bases de datos puedes encontrar el **nombre** del **programa**, el **número** de **ejecuciones**, los **archivos** **abiertos**, el **volumen** **accedido**, la **ruta** **completa**, los **intervalos temporales** y las **marcas de tiempo**.

Puedes acceder a esta información usando la herramienta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **supervisa** los **recursos** **consumidos** **por un proceso**. Apareció en W8 y almacena los datos en una base de datos ESE ubicada en `C:\Windows\System32\sru\SRUDB.dat`.

Proporciona la siguiente información:

- AppID y ruta
- Usuario que ejecutó el proceso
- Bytes enviados
- Bytes recibidos
- Interfaz de red
- Duración de la conexión
- Duración del proceso

Esta información se actualiza cada 60 minutos.

Puedes obtener los datos de este archivo usando la herramienta [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

El **AppCompatCache**, también conocido como **ShimCache**, forma parte de la **Application Compatibility Database** desarrollada por **Microsoft** para resolver problemas de compatibilidad de aplicaciones. Este componente del sistema registra varios datos de metadatos de los archivos, entre ellos:

- Ruta completa del archivo
- Tamaño del archivo
- Hora de última modificación en **$Standard_Information** (SI)
- Hora de última actualización de ShimCache
- Process Execution Flag

Estos datos se almacenan en el registro en ubicaciones específicas según la versión del sistema operativo:

- En XP, los datos se almacenan en `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, con capacidad para 96 entradas.
- En Server 2003, así como en las versiones de Windows 2008, 2012, 2016, 7, 8 y 10, la ruta de almacenamiento es `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, con capacidad para 512 y 1024 entradas, respectivamente.

Para analizar la información almacenada, se recomienda utilizar la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Para analizar la información almacenada, se recomienda utilizar la herramienta AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

El archivo **Amcache.hve** es esencialmente una registry hive que registra información sobre las aplicaciones que se han ejecutado en un sistema. Normalmente se encuentra en `C:\Windows\AppCompat\Programas\Amcache.hve`.

Este archivo destaca por almacenar registros de procesos ejecutados recientemente, incluidas las rutas a los archivos ejecutables y sus hashes SHA1. Esta información es muy valiosa para rastrear la actividad de las aplicaciones en un sistema.

Para extraer y analizar los datos de **Amcache.hve**, se puede utilizar la herramienta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). El siguiente comando muestra un ejemplo de cómo utilizar AmcacheParser para analizar el contenido del archivo **Amcache.hve** y generar los resultados en formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre los archivos CSV generados, `Amcache_Unassociated file entries` es especialmente destacable debido a la gran cantidad de información que proporciona sobre las entradas de archivos no asociadas.

El archivo CVS generado más interesante es `Amcache_Unassociated file entries`.

### RecentFileCache

Este artifact solo se puede encontrar en W7, en `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, y contiene información sobre la ejecución reciente de algunos binarios.

Puedes utilizar la herramienta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analizar el archivo.

### Tareas programadas

Puedes extraerlas de `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` y leerlas como XML.

### Servicios

Puedes encontrarlos en el registro, en `SYSTEM\ControlSet001\Services`. Puedes ver qué se va a ejecutar y cuándo.

### **Windows Store**

Las aplicaciones instaladas se pueden encontrar en `\ProgramData\Microsoft\Windows\AppRepository`\  
Este repositorio contiene un **log** con **cada aplicación instalada** en el sistema dentro de la base de datos **`StateRepository-Machine.srd`**.

Dentro de la tabla Application de esta base de datos, es posible encontrar las columnas: "Application ID", "PackageNumber" y "Display Name". Estas columnas contienen información sobre las aplicaciones preinstaladas e instaladas, y permiten determinar si se desinstalaron algunas aplicaciones, ya que los IDs de las aplicaciones instaladas deberían ser secuenciales.

También es posible **encontrar aplicaciones instaladas** dentro de la ruta del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`\  
Y **aplicaciones** **desinstaladas** en: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos de Windows

La información que aparece dentro de los eventos de Windows incluye:

- Qué ocurrió
- Marca de tiempo (UTC + 0)
- Usuarios implicados
- Hosts implicados (hostname, IP)
- Activos accedidos (archivos, carpetas, impresoras, servicios)

Los logs se encuentran en `C:\Windows\System32\config` antes de Windows Vista y en `C:\Windows\System32\winevt\Logs` después de Windows Vista. Antes de Windows Vista, los logs de eventos estaban en formato binario y, posteriormente, están en **formato XML** y utilizan la extensión **.evtx**.

La ubicación de los archivos de eventos se puede encontrar en el registro SYSTEM, en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Se pueden visualizar desde el Visor de eventos de Windows (**`eventvwr.msc`**) o con otras herramientas como [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprender el registro de eventos de seguridad de Windows

Los eventos de acceso se registran en el archivo de configuración de seguridad ubicado en `C:\Windows\System32\winevt\Security.evtx`. El tamaño de este archivo se puede ajustar y, cuando alcanza su capacidad, los eventos más antiguos se sobrescriben. Los eventos registrados incluyen inicios y cierres de sesión de usuarios, acciones de usuarios y cambios en la configuración de seguridad, así como accesos a archivos, carpetas y activos compartidos.

### IDs de eventos clave para la autenticación de usuarios:

- **EventID 4624**: Indica que un usuario se autenticó correctamente.
- **EventID 4625**: Señala un fallo de autenticación.
- **EventIDs 4634/4647**: Representan eventos de cierre de sesión de usuarios.
- **EventID 4672**: Indica un inicio de sesión con privilegios administrativos.

#### Subtipos dentro de EventID 4634/4647:

- **Interactive (2)**: Inicio de sesión directo de un usuario.
- **Network (3)**: Acceso a carpetas compartidas.
- **Batch (4)**: Ejecución de procesos por lotes.
- **Service (5)**: Inicio de servicios.
- **Proxy (6)**: Autenticación mediante proxy.
- **Unlock (7)**: Pantalla desbloqueada con una contraseña.
- **Network Cleartext (8)**: Transmisión de contraseñas en texto claro, normalmente desde IIS.
- **New Credentials (9)**: Uso de credenciales diferentes para el acceso.
- **Remote Interactive (10)**: Inicio de sesión mediante escritorio remoto o terminal services.
- **Cache Interactive (11)**: Inicio de sesión con credenciales almacenadas en caché sin contactar con el controlador de dominio.
- **Cache Remote Interactive (12)**: Inicio de sesión remoto con credenciales almacenadas en caché.
- **Cached Unlock (13)**: Desbloqueo con credenciales almacenadas en caché.

#### Códigos de estado y subestado para EventID 4625:

- **0xC0000064**: El nombre de usuario no existe - Podría indicar un ataque de enumeración de nombres de usuario.
- **0xC000006A**: Nombre de usuario correcto, pero contraseña incorrecta - Posible intento de adivinación de contraseñas o brute-force.
- **0xC0000234**: La cuenta de usuario está bloqueada - Puede producirse después de un ataque de brute-force que provoque múltiples inicios de sesión fallidos.
- **0xC0000072**: Cuenta deshabilitada - Intentos no autorizados de acceder a cuentas deshabilitadas.
- **0xC000006F**: Inicio de sesión fuera del horario permitido - Indica intentos de acceso fuera del horario de inicio de sesión establecido, una posible señal de acceso no autorizado.
- **0xC0000070**: Infracción de las restricciones de la estación de trabajo - Podría ser un intento de iniciar sesión desde una ubicación no autorizada.
- **0xC0000193**: Cuenta expirada - Intentos de acceso con cuentas de usuario caducadas.
- **0xC0000071**: Contraseña expirada - Intentos de inicio de sesión con contraseñas obsoletas.
- **0xC0000133**: Problemas de sincronización horaria - Las grandes discrepancias de tiempo entre el cliente y el servidor pueden indicar ataques más sofisticados, como pass-the-ticket.
- **0xC0000224**: Se requiere un cambio obligatorio de contraseña - Los cambios obligatorios frecuentes podrían sugerir un intento de desestabilizar la seguridad de la cuenta.
- **0xC0000225**: Indica un error del sistema en lugar de un problema de seguridad.
- **0xC000015b**: Tipo de inicio de sesión denegado - Intento de acceso con un tipo de inicio de sesión no autorizado, como un usuario que intenta ejecutar un inicio de sesión de servicio.

#### EventID 4616:

- **Time Change**: Modificación de la hora del sistema, lo que podría ocultar la cronología de los eventos.

#### EventID 6005 y 6006:

- **System Startup and Shutdown**: EventID 6005 indica que el sistema se está iniciando, mientras que EventID 6006 indica que se está apagando.

#### EventID 1102:

- **Log Deletion**: Borrado de logs de seguridad, lo que suele ser una señal de alerta de que se están encubriendo actividades ilícitas.

#### EventIDs para el seguimiento de dispositivos USB:

- **20001 / 20003 / 10000**: Primera conexión del dispositivo USB.
- **10100**: Actualización del controlador USB.
- **EventID 112**: Momento de inserción del dispositivo USB.

Para consultar ejemplos prácticos sobre la simulación de estos tipos de inicio de sesión y las oportunidades de credential dumping, consulta la guía detallada de [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Los detalles de los eventos, incluidos los códigos de estado y subestado, proporcionan información adicional sobre las causas de los eventos, especialmente en el caso de Event ID 4625.

### Recuperación de eventos de Windows

Para aumentar las posibilidades de recuperar eventos de Windows eliminados, se recomienda apagar el ordenador sospechoso desenchufándolo directamente. Se recomienda **Bulk_extractor**, una herramienta de recuperación que especifica la extensión `.evtx`, para intentar recuperar dichos eventos.

### Identificación de ataques comunes mediante eventos de Windows

Para consultar una guía completa sobre el uso de los Windows Event IDs para identificar ataques cibernéticos comunes, visita [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Ataques de Brute Force

Se pueden identificar mediante múltiples registros EventID 4625, seguidos de un EventID 4624 si el ataque tiene éxito.

#### Cambio de hora

Registrados mediante EventID 4616, los cambios en la hora del sistema pueden complicar el análisis forense.

#### Seguimiento de dispositivos USB

Entre los System EventIDs útiles para el seguimiento de dispositivos USB se incluyen 20001/20003/10000 para el uso inicial, 10100 para las actualizaciones de controladores y EventID 112 de DeviceSetupManager para las marcas de tiempo de inserción.

#### Eventos de alimentación del sistema

EventID 6005 indica el inicio del sistema, mientras que EventID 6006 indica el apagado.

#### Eliminación de logs

Security EventID 1102 indica la eliminación de logs, un evento crítico para el análisis forense.

## Referencias

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
