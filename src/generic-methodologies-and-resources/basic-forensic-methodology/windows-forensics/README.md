# Artefactos de Windows

## Artefactos de Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos Genéricos de Windows

### Notificaciones de Windows 10

En la ruta `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` puedes encontrar la base de datos `appdb.dat` (antes del aniversario de Windows) o `wpndatabase.db` (después del aniversario de Windows).

Dentro de esta base de datos SQLite, puedes encontrar la tabla `Notification` con todas las notificaciones (en formato XML) que pueden contener datos interesantes.

### Línea de Tiempo

La línea de tiempo es una característica de Windows que proporciona **historial cronológico** de páginas web visitadas, documentos editados y aplicaciones ejecutadas.

La base de datos reside en la ruta `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Esta base de datos se puede abrir con una herramienta SQLite o con la herramienta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **que genera 2 archivos que se pueden abrir con la herramienta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Flujos de Datos Alternativos)

Los archivos descargados pueden contener el **ADS Zone.Identifier** que indica **cómo** fue **descargado** desde la intranet, internet, etc. Algunos programas (como navegadores) suelen poner incluso **más** **información** como la **URL** desde donde se descargó el archivo.

## **Copias de Seguridad de Archivos**

### Papelera de Reciclaje

En Vista/Win7/Win8/Win10 la **Papelera de Reciclaje** se puede encontrar en la carpeta **`$Recycle.bin`** en la raíz de la unidad (`C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta se crean 2 archivos específicos:

- `$I{id}`: Información del archivo (fecha de cuando fue eliminado)
- `$R{id}`: Contenido del archivo

![](<../../../images/image (1029).png>)

Teniendo estos archivos puedes usar la herramienta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obtener la dirección original de los archivos eliminados y la fecha en que fueron eliminados (usa `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### Copias de Sombra de Volumen

Shadow Copy es una tecnología incluida en Microsoft Windows que puede crear **copias de seguridad** o instantáneas de archivos o volúmenes de computadora, incluso cuando están en uso.

Estas copias de seguridad generalmente se encuentran en `\System Volume Information` desde la raíz del sistema de archivos y el nombre está compuesto por **UIDs** que se muestran en la siguiente imagen:

![](<../../../images/image (94).png>)

Montando la imagen forense con **ArsenalImageMounter**, se puede usar la herramienta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) para inspeccionar una copia de sombra e incluso **extraer los archivos** de las copias de seguridad de la copia de sombra.

![](<../../../images/image (576).png>)

La entrada del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene los archivos y claves **para no hacer copia de seguridad**:

![](<../../../images/image (254).png>)

El registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene información de configuración sobre las `Copias de Sombra de Volumen`.

### Archivos de Office AutoGuardados

Puedes encontrar los archivos de auto guardado de Office en: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementos de Shell

Un elemento de shell es un elemento que contiene información sobre cómo acceder a otro archivo.

### Documentos Recientes (LNK)

Windows **crea automáticamente** estos **accesos directos** cuando el usuario **abre, usa o crea un archivo** en:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Cuando se crea una carpeta, también se crea un enlace a la carpeta, a la carpeta padre y a la carpeta abuela.

Estos archivos de enlace creados automáticamente **contienen información sobre el origen** como si es un **archivo** **o** una **carpeta**, **tiempos MAC** de ese archivo, **información de volumen** de dónde está almacenado el archivo y **carpeta del archivo objetivo**. Esta información puede ser útil para recuperar esos archivos en caso de que hayan sido eliminados.

Además, la **fecha de creación del enlace** es la primera **vez** que se **usó** el archivo original y la **fecha** **modificada** del archivo de enlace es la **última** **vez** que se usó el archivo de origen.

Para inspeccionar estos archivos puedes usar [**LinkParser**](http://4discovery.com/our-tools/).

En esta herramienta encontrarás **2 conjuntos** de marcas de tiempo:

- **Primer Conjunto:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Segundo Conjunto:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

El primer conjunto de marcas de tiempo hace referencia a las **marcas de tiempo del archivo en sí**. El segundo conjunto hace referencia a las **marcas de tiempo del archivo vinculado**.

Puedes obtener la misma información ejecutando la herramienta de línea de comandos de Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
En este caso, la información se va a guardar dentro de un archivo CSV.

### Jumplists

Estos son los archivos recientes que se indican por aplicación. Es la lista de **archivos recientes utilizados por una aplicación** a los que puedes acceder en cada aplicación. Pueden ser creados **automáticamente o ser personalizados**.

Los **jumplists** creados automáticamente se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Los jumplists se nombran siguiendo el formato `{id}.autmaticDestinations-ms` donde el ID inicial es el ID de la aplicación.

Los jumplists personalizados se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` y son creados por la aplicación generalmente porque algo **importante** ha sucedido con el archivo (quizás marcado como favorito).

El **tiempo de creación** de cualquier jumplist indica **la primera vez que se accedió al archivo** y el **tiempo modificado la última vez**.

Puedes inspeccionar los jumplists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../images/image (168).png>)

(_Nota que las marcas de tiempo proporcionadas por JumplistExplorer están relacionadas con el archivo jumplist en sí_)

### Shellbags

[**Sigue este enlace para aprender qué son los shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de USBs en Windows

Es posible identificar que se utilizó un dispositivo USB gracias a la creación de:

- Carpeta Reciente de Windows
- Carpeta Reciente de Microsoft Office
- Jumplists

Ten en cuenta que algunos archivos LNK en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE:

![](<../../../images/image (218).png>)

Los archivos en la carpeta WPDNSE son una copia de los originales, por lo que no sobrevivirán a un reinicio del PC y el GUID se toma de un shellbag.

### Información del Registro

[Consulta esta página para aprender](interesting-windows-registry-keys.md#usb-information) qué claves del registro contienen información interesante sobre dispositivos USB conectados.

### setupapi

Consulta el archivo `C:\Windows\inf\setupapi.dev.log` para obtener las marcas de tiempo sobre cuándo se produjo la conexión USB (busca `Section start`).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) se puede usar para obtener información sobre los dispositivos USB que han sido conectados a una imagen.

![](<../../../images/image (452).png>)

### Limpieza de Plug and Play

La tarea programada conocida como 'Limpieza de Plug and Play' está diseñada principalmente para la eliminación de versiones de controladores obsoletas. Contrario a su propósito especificado de retener la última versión del paquete de controladores, fuentes en línea sugieren que también apunta a controladores que han estado inactivos durante 30 días. En consecuencia, los controladores de dispositivos extraíbles no conectados en los últimos 30 días pueden ser objeto de eliminación.

La tarea se encuentra en la siguiente ruta: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Se proporciona una captura de pantalla que muestra el contenido de la tarea: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes Clave y Configuraciones de la Tarea:**

- **pnpclean.dll**: Este DLL es responsable del proceso de limpieza real.
- **UseUnifiedSchedulingEngine**: Establecido en `TRUE`, indicando el uso del motor de programación de tareas genérico.
- **MaintenanceSettings**:
- **Period ('P1M')**: Indica al Programador de Tareas que inicie la tarea de limpieza mensualmente durante el mantenimiento automático regular.
- **Deadline ('P2M')**: Instruye al Programador de Tareas, si la tarea falla durante dos meses consecutivos, a ejecutar la tarea durante el mantenimiento automático de emergencia.

Esta configuración asegura un mantenimiento y limpieza regular de los controladores, con disposiciones para reintentar la tarea en caso de fallos consecutivos.

**Para más información consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Correos Electrónicos

Los correos electrónicos contienen **2 partes interesantes: Los encabezados y el contenido** del correo. En los **encabezados** puedes encontrar información como:

- **Quién** envió los correos (dirección de correo, IP, servidores de correo que han redirigido el correo)
- **Cuándo** se envió el correo

Además, dentro de los encabezados `References` e `In-Reply-To` puedes encontrar el ID de los mensajes:

![](<../../../images/image (593).png>)

### Aplicación de Correo de Windows

Esta aplicación guarda correos en HTML o texto. Puedes encontrar los correos dentro de subcarpetas en `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Los correos se guardan con la extensión `.dat`.

Los **metadatos** de los correos y los **contactos** se pueden encontrar dentro de la **base de datos EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia la extensión** del archivo de `.vol` a `.edb` y puedes usar la herramienta [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) para abrirlo. Dentro de la tabla `Message` puedes ver los correos.

### Microsoft Outlook

Cuando se utilizan servidores Exchange o clientes de Outlook, habrá algunos encabezados MAPI:

- `Mapi-Client-Submit-Time`: Hora del sistema cuando se envió el correo
- `Mapi-Conversation-Index`: Número de mensajes hijos del hilo y marca de tiempo de cada mensaje del hilo
- `Mapi-Entry-ID`: Identificador del mensaje.
- `Mappi-Message-Flags` y `Pr_last_Verb-Executed`: Información sobre el cliente MAPI (¿mensaje leído? ¿no leído? ¿respondido? ¿redirigido? ¿fuera de la oficina?)

En el cliente de Microsoft Outlook, todos los mensajes enviados/recibidos, datos de contactos y datos de calendario se almacenan en un archivo PST en:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

La ruta del registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica el archivo que se está utilizando.

Puedes abrir el archivo PST usando la herramienta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../images/image (498).png>)

### Archivos OST de Microsoft Outlook

Un **archivo OST** es generado por Microsoft Outlook cuando está configurado con **IMAP** o un servidor **Exchange**, almacenando información similar a un archivo PST. Este archivo se sincroniza con el servidor, reteniendo datos por **los últimos 12 meses** hasta un **tamaño máximo de 50GB**, y se encuentra en el mismo directorio que el archivo PST. Para ver un archivo OST, se puede utilizar el [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recuperando Adjuntos

Los adjuntos perdidos podrían ser recuperables de:

- Para **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Para **IE11 y superiores**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Archivos MBOX de Thunderbird

**Thunderbird** utiliza **archivos MBOX** para almacenar datos, ubicados en `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturas de Imágenes

- **Windows XP y 8-8.1**: Acceder a una carpeta con miniaturas genera un archivo `thumbs.db` que almacena vistas previas de imágenes, incluso después de la eliminación.
- **Windows 7/10**: `thumbs.db` se crea cuando se accede a través de una red mediante una ruta UNC.
- **Windows Vista y versiones más recientes**: Las vistas previas de miniaturas se centralizan en `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` con archivos llamados **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) y [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) son herramientas para ver estos archivos.

### Información del Registro de Windows

El Registro de Windows, que almacena una extensa cantidad de datos sobre la actividad del sistema y del usuario, se encuentra dentro de archivos en:

- `%windir%\System32\Config` para varias subclaves de `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` para `HKEY_CURRENT_USER`.
- Windows Vista y versiones posteriores respaldan los archivos del registro de `HKEY_LOCAL_MACHINE` en `%Windir%\System32\Config\RegBack\`.
- Además, la información sobre la ejecución de programas se almacena en `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` desde Windows Vista y Windows 2008 Server en adelante.

### Herramientas

Algunas herramientas son útiles para analizar los archivos del registro:

- **Editor del Registro**: Está instalado en Windows. Es una GUI para navegar a través del registro de Windows de la sesión actual.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite cargar el archivo del registro y navegar a través de él con una GUI. También contiene Marcadores que destacan claves con información interesante.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Nuevamente, tiene una GUI que permite navegar a través del registro cargado y también contiene complementos que destacan información interesante dentro del registro cargado.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Otra aplicación GUI capaz de extraer la información importante del registro cargado.

### Recuperando Elementos Eliminados

Cuando se elimina una clave, se marca como tal, pero hasta que el espacio que ocupa sea necesario, no se eliminará. Por lo tanto, usando herramientas como **Registry Explorer** es posible recuperar estas claves eliminadas.

### Última Hora de Escritura

Cada Clave-Valor contiene una **marca de tiempo** que indica la última vez que fue modificada.

### SAM

El archivo/hive **SAM** contiene los **usuarios, grupos y hashes de contraseñas de los usuarios** del sistema.

En `SAM\Domains\Account\Users` puedes obtener el nombre de usuario, el RID, el último inicio de sesión, el último inicio de sesión fallido, el contador de inicios de sesión, la política de contraseñas y cuándo se creó la cuenta. Para obtener los **hashes** también **necesitas** el archivo/hive **SYSTEM**.

### Entradas Interesantes en el Registro de Windows

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programas Ejecutados

### Procesos Básicos de Windows

En [esta publicación](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) puedes aprender sobre los procesos comunes de Windows para detectar comportamientos sospechosos.

### Aplicaciones Recientes de Windows

Dentro del registro `NTUSER.DAT` en la ruta `Software\Microsoft\Current Version\Search\RecentApps` puedes encontrar subclaves con información sobre la **aplicación ejecutada**, **última vez** que fue ejecutada, y **número de veces** que fue lanzada.

### BAM (Moderador de Actividad en Segundo Plano)

Puedes abrir el archivo `SYSTEM` con un editor de registro y dentro de la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` puedes encontrar la información sobre las **aplicaciones ejecutadas por cada usuario** (nota el `{SID}` en la ruta) y a **qué hora** fueron ejecutadas (la hora está dentro del valor de datos del registro).

### Prefetch de Windows

El prefetching es una técnica que permite a una computadora **obtener silenciosamente los recursos necesarios para mostrar contenido** que un usuario **podría acceder en un futuro cercano** para que los recursos puedan ser accedidos más rápido.

El prefetch de Windows consiste en crear **cachés de los programas ejecutados** para poder cargarlos más rápido. Estas cachés se crean como archivos `.pf` dentro de la ruta: `C:\Windows\Prefetch`. Hay un límite de 128 archivos en XP/VISTA/WIN7 y 1024 archivos en Win8/Win10.

El nombre del archivo se crea como `{program_name}-{hash}.pf` (el hash se basa en la ruta y argumentos del ejecutable). En W10, estos archivos están comprimidos. Ten en cuenta que la sola presencia del archivo indica que **el programa fue ejecutado** en algún momento.

El archivo `C:\Windows\Prefetch\Layout.ini` contiene los **nombres de las carpetas de los archivos que se prefetch**. Este archivo contiene **información sobre el número de ejecuciones**, **fechas** de la ejecución y **archivos** **abiertos** por el programa.

Para inspeccionar estos archivos puedes usar la herramienta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** tiene el mismo objetivo que prefetch, **cargar programas más rápido** al predecir qué se va a cargar a continuación. Sin embargo, no sustituye el servicio de prefetch.\
Este servicio generará archivos de base de datos en `C:\Windows\Prefetch\Ag*.db`.

En estas bases de datos puedes encontrar el **nombre** del **programa**, **número** de **ejecuciones**, **archivos** **abiertos**, **volumen** **accedido**, **ruta** **completa**, **intervalos de tiempo** y **marcas de tiempo**.

Puedes acceder a esta información utilizando la herramienta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitorea** los **recursos** **consumidos** **por un proceso**. Apareció en W8 y almacena los datos en una base de datos ESE ubicada en `C:\Windows\System32\sru\SRUDB.dat`.

Proporciona la siguiente información:

- AppID y Ruta
- Usuario que ejecutó el proceso
- Bytes Enviados
- Bytes Recibidos
- Interfaz de Red
- Duración de la Conexión
- Duración del Proceso

Esta información se actualiza cada 60 minutos.

Puedes obtener la fecha de este archivo utilizando la herramienta [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

El **AppCompatCache**, también conocido como **ShimCache**, forma parte de la **Base de Datos de Compatibilidad de Aplicaciones** desarrollada por **Microsoft** para abordar problemas de compatibilidad de aplicaciones. Este componente del sistema registra varias piezas de metadatos de archivos, que incluyen:

- Ruta completa del archivo
- Tamaño del archivo
- Hora de última modificación bajo **$Standard_Information** (SI)
- Hora de última actualización del ShimCache
- Bandera de ejecución del proceso

Estos datos se almacenan en el registro en ubicaciones específicas según la versión del sistema operativo:

- Para XP, los datos se almacenan en `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` con una capacidad para 96 entradas.
- Para Server 2003, así como para las versiones de Windows 2008, 2012, 2016, 7, 8 y 10, la ruta de almacenamiento es `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, acomodando 512 y 1024 entradas, respectivamente.

Para analizar la información almacenada, se recomienda utilizar la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../images/image (75).png>)

### Amcache

El archivo **Amcache.hve** es esencialmente un hive del registro que registra detalles sobre las aplicaciones que se han ejecutado en un sistema. Se encuentra típicamente en `C:\Windows\AppCompat\Programas\Amcache.hve`.

Este archivo es notable por almacenar registros de procesos ejecutados recientemente, incluyendo las rutas a los archivos ejecutables y sus hashes SHA1. Esta información es invaluable para rastrear la actividad de las aplicaciones en un sistema.

Para extraer y analizar los datos de **Amcache.hve**, se puede utilizar la herramienta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). El siguiente comando es un ejemplo de cómo usar AmcacheParser para analizar el contenido del archivo **Amcache.hve** y exportar los resultados en formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre los archivos CSV generados, el `Amcache_Unassociated file entries` es particularmente notable debido a la rica información que proporciona sobre las entradas de archivos no asociadas.

El archivo CVS más interesante generado es el `Amcache_Unassociated file entries`.

### RecentFileCache

Este artefacto solo se puede encontrar en W7 en `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` y contiene información sobre la ejecución reciente de algunos binarios.

Puedes usar la herramienta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analizar el archivo.

### Tareas programadas

Puedes extraerlas de `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` y leerlas como XML.

### Servicios

Puedes encontrarlos en el registro bajo `SYSTEM\ControlSet001\Services`. Puedes ver qué se va a ejecutar y cuándo.

### **Windows Store**

Las aplicaciones instaladas se pueden encontrar en `\ProgramData\Microsoft\Windows\AppRepository\`\
Este repositorio tiene un **log** con **cada aplicación instalada** en el sistema dentro de la base de datos **`StateRepository-Machine.srd`**.

Dentro de la tabla de Aplicaciones de esta base de datos, es posible encontrar las columnas: "Application ID", "PackageNumber" y "Display Name". Estas columnas tienen información sobre aplicaciones preinstaladas e instaladas y se puede encontrar si algunas aplicaciones fueron desinstaladas porque los IDs de las aplicaciones instaladas deberían ser secuenciales.

También es posible **encontrar aplicaciones instaladas** dentro de la ruta del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Y **aplicaciones desinstaladas** en: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos de Windows

La información que aparece dentro de los eventos de Windows es:

- Qué sucedió
- Marca de tiempo (UTC + 0)
- Usuarios involucrados
- Hosts involucrados (nombre de host, IP)
- Activos accedidos (archivos, carpetas, impresoras, servicios)

Los registros se encuentran en `C:\Windows\System32\config` antes de Windows Vista y en `C:\Windows\System32\winevt\Logs` después de Windows Vista. Antes de Windows Vista, los registros de eventos estaban en formato binario y después de eso, están en **formato XML** y utilizan la extensión **.evtx**.

La ubicación de los archivos de eventos se puede encontrar en el registro del SISTEMA en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Se pueden visualizar desde el Visor de Eventos de Windows (**`eventvwr.msc`**) o con otras herramientas como [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprendiendo el registro de eventos de seguridad de Windows

Los eventos de acceso se registran en el archivo de configuración de seguridad ubicado en `C:\Windows\System32\winevt\Security.evtx`. El tamaño de este archivo es ajustable, y cuando se alcanza su capacidad, los eventos más antiguos se sobrescriben. Los eventos registrados incluyen inicios y cierres de sesión de usuarios, acciones de usuarios y cambios en la configuración de seguridad, así como acceso a archivos, carpetas y activos compartidos.

### IDs de eventos clave para la autenticación de usuarios:

- **EventID 4624**: Indica que un usuario se autenticó con éxito.
- **EventID 4625**: Señala un fallo de autenticación.
- **EventIDs 4634/4647**: Representan eventos de cierre de sesión de usuarios.
- **EventID 4672**: Denota inicio de sesión con privilegios administrativos.

#### Subtipos dentro de EventID 4634/4647:

- **Interactivo (2)**: Inicio de sesión directo del usuario.
- **Red (3)**: Acceso a carpetas compartidas.
- **Lote (4)**: Ejecución de procesos por lotes.
- **Servicio (5)**: Lanzamientos de servicios.
- **Proxy (6)**: Autenticación proxy.
- **Desbloquear (7)**: Pantalla desbloqueada con una contraseña.
- **Texto claro de red (8)**: Transmisión de contraseña en texto claro, a menudo desde IIS.
- **Nuevas credenciales (9)**: Uso de diferentes credenciales para el acceso.
- **Interactivo remoto (10)**: Inicio de sesión en escritorio remoto o servicios de terminal.
- **Interactivo en caché (11)**: Inicio de sesión con credenciales en caché sin contacto con el controlador de dominio.
- **Interactivo remoto en caché (12)**: Inicio de sesión remoto con credenciales en caché.
- **Desbloqueo en caché (13)**: Desbloqueo con credenciales en caché.

#### Códigos de estado y subestado para EventID 4625:

- **0xC0000064**: El nombre de usuario no existe - Podría indicar un ataque de enumeración de nombres de usuario.
- **0xC000006A**: Nombre de usuario correcto pero contraseña incorrecta - Posible intento de adivinanza de contraseña o fuerza bruta.
- **0xC0000234**: Cuenta de usuario bloqueada - Puede seguir a un ataque de fuerza bruta que resulte en múltiples inicios de sesión fallidos.
- **0xC0000072**: Cuenta deshabilitada - Intentos no autorizados de acceder a cuentas deshabilitadas.
- **0xC000006F**: Inicio de sesión fuera del tiempo permitido - Indica intentos de acceso fuera de las horas de inicio de sesión establecidas, un posible signo de acceso no autorizado.
- **0xC0000070**: Violación de restricciones de estación de trabajo - Podría ser un intento de inicio de sesión desde una ubicación no autorizada.
- **0xC0000193**: Expiración de cuenta - Intentos de acceso con cuentas de usuario expiradas.
- **0xC0000071**: Contraseña expirada - Intentos de inicio de sesión con contraseñas desactualizadas.
- **0xC0000133**: Problemas de sincronización de tiempo - Grandes discrepancias de tiempo entre el cliente y el servidor pueden ser indicativas de ataques más sofisticados como pass-the-ticket.
- **0xC0000224**: Se requiere cambio de contraseña obligatorio - Cambios obligatorios frecuentes podrían sugerir un intento de desestabilizar la seguridad de la cuenta.
- **0xC0000225**: Indica un error del sistema en lugar de un problema de seguridad.
- **0xC000015b**: Tipo de inicio de sesión denegado - Intento de acceso con un tipo de inicio de sesión no autorizado, como un usuario que intenta ejecutar un inicio de sesión de servicio.

#### EventID 4616:

- **Cambio de hora**: Modificación de la hora del sistema, podría oscurecer la línea de tiempo de los eventos.

#### EventID 6005 y 6006:

- **Inicio y apagado del sistema**: EventID 6005 indica que el sistema se está iniciando, mientras que EventID 6006 marca su apagado.

#### EventID 1102:

- **Eliminación de registros**: Los registros de seguridad están siendo borrados, lo que a menudo es una señal de alerta para encubrir actividades ilícitas.

#### EventIDs para el seguimiento de dispositivos USB:

- **20001 / 20003 / 10000**: Primera conexión del dispositivo USB.
- **10100**: Actualización del controlador USB.
- **EventID 112**: Hora de inserción del dispositivo USB.

Para ejemplos prácticos sobre cómo simular estos tipos de inicio de sesión y oportunidades de volcado de credenciales, consulta la [guía detallada de Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Los detalles del evento, incluidos los códigos de estado y subestado, proporcionan más información sobre las causas del evento, particularmente notables en el Event ID 4625.

### Recuperando eventos de Windows

Para aumentar las posibilidades de recuperar eventos de Windows eliminados, se recomienda apagar la computadora sospechosa desconectándola directamente. **Bulk_extractor**, una herramienta de recuperación que especifica la extensión `.evtx`, se recomienda para intentar recuperar tales eventos.

### Identificando ataques comunes a través de eventos de Windows

Para una guía completa sobre cómo utilizar los IDs de eventos de Windows para identificar ataques cibernéticos comunes, visita [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Ataques de fuerza bruta

Identificables por múltiples registros de EventID 4625, seguidos de un EventID 4624 si el ataque tiene éxito.

#### Cambio de hora

Registrado por EventID 4616, los cambios en la hora del sistema pueden complicar el análisis forense.

#### Seguimiento de dispositivos USB

IDs de eventos del sistema útiles para el seguimiento de dispositivos USB incluyen 20001/20003/10000 para el uso inicial, 10100 para actualizaciones de controladores y EventID 112 de DeviceSetupManager para marcas de tiempo de inserción.

#### Eventos de energía del sistema

EventID 6005 indica el inicio del sistema, mientras que EventID 6006 marca el apagado.

#### Eliminación de registros

El EventID de seguridad 1102 señala la eliminación de registros, un evento crítico para el análisis forense.

{{#include ../../../banners/hacktricks-training.md}}
