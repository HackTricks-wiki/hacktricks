# Artefactos de Windows

## Artefactos de Windows

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Artefactos Genéricos de Windows

### Notificaciones de Windows 10

En la ruta `\Users\<nombredeusuario>\AppData\Local\Microsoft\Windows\Notifications` puedes encontrar la base de datos `appdb.dat` (antes del aniversario de Windows) o `wpndatabase.db` (después del aniversario de Windows).

Dentro de esta base de datos SQLite, puedes encontrar la tabla `Notification` con todas las notificaciones (en formato XML) que pueden contener datos interesantes.

### Línea de Tiempo

La Línea de Tiempo es una característica de Windows que proporciona un **historial cronológico** de las páginas web visitadas, documentos editados y aplicaciones ejecutadas.

La base de datos reside en la ruta `\Users\<nombredeusuario>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Esta base de datos se puede abrir con una herramienta SQLite o con la herramienta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **que genera 2 archivos que se pueden abrir con la herramienta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Flujos de Datos Alternativos)

Los archivos descargados pueden contener la **Zona de Identificación de ADS** que indica **cómo** fue **descargado** de la intranet, internet, etc. Algunos software (como navegadores) suelen incluir **más** **información** como la **URL** desde donde se descargó el archivo.

## **Copias de Seguridad de Archivos**

### Papelera de Reciclaje

En Vista/Win7/Win8/Win10 la **Papelera de Reciclaje** se puede encontrar en la carpeta **`$Recycle.bin`** en la raíz de la unidad (`C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta se crean 2 archivos específicos:

* `$I{id}`: Información del archivo (fecha en que fue eliminado)
* `$R{id}`: Contenido del archivo

![](<../../../.gitbook/assets/image (1029).png>)

Teniendo estos archivos, puedes usar la herramienta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obtener la dirección original de los archivos eliminados y la fecha en que fueron eliminados (usa `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Copias de sombra del volumen

Shadow Copy es una tecnología incluida en Microsoft Windows que puede crear **copias de seguridad** o instantáneas de archivos o volúmenes de computadora, incluso cuando están en uso.

Estas copias de seguridad suelen estar ubicadas en `\System Volume Information` desde la raíz del sistema de archivos y el nombre está compuesto por **UIDs** mostrados en la siguiente imagen:

![](<../../../.gitbook/assets/image (94).png>)

Al montar la imagen forense con **ArsenalImageMounter**, la herramienta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) se puede utilizar para inspeccionar una copia de sombra e incluso **extraer los archivos** de las copias de seguridad de la copia de sombra.

![](<../../../.gitbook/assets/image (576).png>)

La entrada del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene los archivos y claves **que no se deben respaldar**:

![](<../../../.gitbook/assets/image (254).png>)

El registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene información de configuración sobre las `Volume Shadow Copies`.

### Archivos de autoguardado de Office

Puede encontrar los archivos de autoguardado de Office en: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementos de Shell

Un elemento de shell es un elemento que contiene información sobre cómo acceder a otro archivo.

### Documentos recientes (LNK)

Windows **crea automáticamente** estos **accesos directos** cuando el usuario **abre, usa o crea un archivo** en:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Cuando se crea una carpeta, también se crea un enlace a la carpeta, a la carpeta principal y a la carpeta abuela.

Estos archivos de enlace creados automáticamente **contienen información sobre el origen** como si es un **archivo** **o** una **carpeta**, **tiempos MAC** de ese archivo, **información de volumen** de dónde se encuentra almacenado el archivo y **carpeta del archivo de destino**. Esta información puede ser útil para recuperar esos archivos en caso de que sean eliminados.

Además, la **fecha de creación del archivo de enlace** es la primera **vez** que se **usó** el archivo original y la **fecha** **modificada** del archivo de enlace es la **última** **vez** que se usó el archivo de origen.

Para inspeccionar estos archivos, puede utilizar [**LinkParser**](http://4discovery.com/our-tools/).

En esta herramienta encontrará **2 conjuntos** de marcas de tiempo:

* **Primer conjunto:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Segundo conjunto:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

El primer conjunto de marcas de tiempo hace referencia a las **marcas de tiempo del archivo en sí**. El segundo conjunto hace referencia a las **marcas de tiempo del archivo vinculado**.

Puede obtener la misma información ejecutando la herramienta de línea de comandos de Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
En este caso, la información se guardará dentro de un archivo CSV.

### Jumplists

Estas son los archivos recientes indicados por aplicación. Es la lista de **archivos recientes utilizados por una aplicación** a la que se puede acceder en cada aplicación. Pueden ser creados **automáticamente o personalizados**.

Los **jumplists** creados automáticamente se almacenan en `C:\Users\{nombre de usuario}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Los jumplists se nombran siguiendo el formato `{id}.autmaticDestinations-ms` donde el ID inicial es el ID de la aplicación.

Los jumplists personalizados se almacenan en `C:\Users\{nombre de usuario}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` y son creados por la aplicación generalmente porque algo **importante** ha sucedido con el archivo (quizás marcado como favorito).

El **tiempo de creación** de cualquier jumplist indica **la primera vez que se accedió al archivo** y el **tiempo modificado la última vez**.

Puedes inspeccionar los jumplists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (168).png>)

(_Ten en cuenta que las marcas de tiempo proporcionadas por JumplistExplorer están relacionadas con el archivo de jumplist en sí_)

### Shellbags

[**Sigue este enlace para aprender qué son las shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de USB en Windows

Es posible identificar que se utilizó un dispositivo USB gracias a la creación de:

* Carpeta Reciente de Windows
* Carpeta Reciente de Microsoft Office
* Jumplists

Ten en cuenta que algunos archivos LNK en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE:

![](<../../../.gitbook/assets/image (218).png>)

Los archivos en la carpeta WPDNSE son una copia de los originales, por lo que no sobrevivirán a un reinicio de la PC y el GUID se toma de una shellbag.

### Información del Registro

[Consulta esta página para aprender](interesting-windows-registry-keys.md#usb-information) qué claves del registro contienen información interesante sobre dispositivos USB conectados.

### setupapi

Consulta el archivo `C:\Windows\inf\setupapi.dev.log` para obtener las marcas de tiempo sobre cuándo se produjo la conexión USB (busca `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) se puede utilizar para obtener información sobre los dispositivos USB que se han conectado a una imagen.

![](<../../../.gitbook/assets/image (452).png>)

### Limpieza de Plug and Play

La tarea programada conocida como 'Limpieza de Plug and Play' está diseñada principalmente para la eliminación de versiones de controladores obsoletas. Contrariamente a su propósito especificado de retener la última versión del paquete de controladores, fuentes en línea sugieren que también se dirige a controladores que han estado inactivos durante 30 días. En consecuencia, los controladores de dispositivos extraíbles no conectados en los últimos 30 días pueden estar sujetos a eliminación.

La tarea se encuentra en la siguiente ruta: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Se proporciona una captura de pantalla que muestra el contenido de la tarea: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes clave y configuraciones de la tarea:**

* **pnpclean.dll**: Esta DLL es responsable del proceso real de limpieza.
* **UseUnifiedSchedulingEngine**: Establecido en `TRUE`, indicando el uso del motor de programación de tareas genérico.
* **MaintenanceSettings**:
* **Period ('P1M')**: Indica al Programador de tareas que inicie la tarea de limpieza mensualmente durante el mantenimiento automático regular.
* **Deadline ('P2M')**: Instruye al Programador de tareas, si la tarea falla durante dos meses consecutivos, a ejecutar la tarea durante el mantenimiento automático de emergencia.

Esta configuración garantiza el mantenimiento regular y la limpieza de controladores, con disposiciones para volver a intentar la tarea en caso de fallas consecutivas.

**Para obtener más información, consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Correos electrónicos

Los correos electrónicos contienen **2 partes interesantes: Los encabezados y el contenido** del correo electrónico. En los **encabezados** puedes encontrar información como:

* **Quién** envió los correos electrónicos (dirección de correo electrónico, IP, servidores de correo que han redirigido el correo)
* **Cuándo** se envió el correo electrónico

Además, dentro de los encabezados `References` e `In-Reply-To` puedes encontrar el ID de los mensajes:

![](<../../../.gitbook/assets/image (593).png>)

### Aplicación Correo de Windows

Esta aplicación guarda correos electrónicos en HTML o texto. Puedes encontrar los correos electrónicos dentro de subcarpetas en `\Users\<nombre de usuario>\AppData\Local\Comms\Unistore\data\3\`. Los correos electrónicos se guardan con la extensión `.dat`.

Los **metadatos** de los correos electrónicos y los **contactos** se pueden encontrar dentro de la **base de datos EDB**: `\Users\<nombre de usuario>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia la extensión** del archivo de `.vol` a `.edb` y puedes usar la herramienta [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) para abrirlo. Dentro de la tabla `Message` puedes ver los correos electrónicos.

### Microsoft Outlook

Cuando se utilizan servidores Exchange o clientes de Outlook, habrá algunos encabezados MAPI:

* `Mapi-Client-Submit-Time`: Hora del sistema cuando se envió el correo electrónico
* `Mapi-Conversation-Index`: Número de mensajes secundarios del hilo y marca de tiempo de cada mensaje del hilo
* `Mapi-Entry-ID`: Identificador del mensaje.
* `Mappi-Message-Flags` y `Pr_last_Verb-Executed`: Información sobre el cliente MAPI (¿mensaje leído? ¿no leído? ¿respondido? ¿redirigido? ¿fuera de la oficina?)

En el cliente Microsoft Outlook, todos los mensajes enviados/recibidos, datos de contactos y datos de calendario se almacenan en un archivo PST en:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

La ruta del registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica el archivo que se está utilizando.

Puedes abrir el archivo PST utilizando la herramienta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (498).png>)
### Archivos OST de Microsoft Outlook

Un archivo **OST** es generado por Microsoft Outlook cuando está configurado con un servidor **IMAP** o de **Exchange**, almacenando información similar a un archivo PST. Este archivo se sincroniza con el servidor, reteniendo datos durante **los últimos 12 meses** hasta un **tamaño máximo de 50GB**, y se encuentra en el mismo directorio que el archivo PST. Para ver un archivo OST, se puede utilizar el [**visor de OST Kernel**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recuperación de Adjuntos

Los adjuntos perdidos podrían ser recuperables desde:

* Para **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Para **IE11 y superior**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Archivos MBOX de Thunderbird

**Thunderbird** utiliza archivos **MBOX** para almacenar datos, ubicados en `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturas de Imágenes

* **Windows XP y 8-8.1**: Acceder a una carpeta con miniaturas genera un archivo `thumbs.db` que almacena vistas previas de imágenes, incluso después de la eliminación.
* **Windows 7/10**: `thumbs.db` se crea al acceder a través de una red mediante una ruta UNC.
* **Windows Vista y versiones más recientes**: Las vistas previas de miniaturas se centralizan en `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` con archivos nombrados **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) y [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) son herramientas para ver estos archivos.

### Información del Registro de Windows

El Registro de Windows, que almacena datos extensos de actividad del sistema y del usuario, se encuentra en archivos en:

* `%windir%\System32\Config` para varias subclaves de `HKEY_LOCAL_MACHINE`.
* `%UserProfile%{User}\NTUSER.DAT` para `HKEY_CURRENT_USER`.
* Windows Vista y versiones posteriores hacen copias de seguridad de los archivos del registro de `HKEY_LOCAL_MACHINE` en `%Windir%\System32\Config\RegBack\`.
* Además, la información de ejecución de programas se almacena en `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` desde Windows Vista y Windows 2008 Server en adelante.

### Herramientas

Algunas herramientas son útiles para analizar los archivos del registro:

* **Editor de Registro**: Viene instalado en Windows. Es una interfaz gráfica para navegar por el registro de Windows de la sesión actual.
* [**Explorador de Registro**](https://ericzimmerman.github.io/#!index.md): Permite cargar el archivo del registro y navegar a través de ellos con una interfaz gráfica. También contiene Marcadores que resaltan claves con información interesante.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Nuevamente, tiene una interfaz gráfica que permite navegar por el registro cargado y también contiene complementos que resaltan información interesante dentro del registro cargado.
* [**Recuperación del Registro de Windows**](https://www.mitec.cz/wrr.html): Otra aplicación con interfaz gráfica capaz de extraer la información importante del registro cargado.

### Recuperación de Elementos Eliminados

Cuando se elimina una clave, se marca como tal, pero hasta que se necesite el espacio que ocupa, no se eliminará. Por lo tanto, utilizando herramientas como **Explorador de Registro**, es posible recuperar estas claves eliminadas.

### Hora de Última Escritura

Cada Clave-Valor contiene una **marca de tiempo** que indica la última vez que fue modificada.

### SAM

El archivo/base de datos **SAM** contiene los **hashes de contraseñas de usuarios, grupos y usuarios** del sistema.

En `SAM\Domains\Account\Users` se puede obtener el nombre de usuario, el RID, último inicio de sesión, último inicio de sesión fallido, contador de inicio de sesión, política de contraseñas y cuándo se creó la cuenta. Para obtener los **hashes** también se **necesita** el archivo/base de datos **SYSTEM**.

### Entradas Interesantes en el Registro de Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programas Ejecutados

### Procesos Básicos de Windows

En [este post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) puedes aprender sobre los procesos comunes de Windows para detectar comportamientos sospechosos.

### Aplicaciones Recientes de Windows

Dentro del registro `NTUSER.DAT` en la ruta `Software\Microsoft\Current Version\Search\RecentApps` puedes encontrar subclaves con información sobre la **aplicación ejecutada**, la **última vez** que se ejecutó y el **número de veces** que se lanzó.

### BAM (Moderador de Actividad en Segundo Plano)

Puedes abrir el archivo `SYSTEM` con un editor de registro y dentro de la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` puedes encontrar la información sobre las **aplicaciones ejecutadas por cada usuario** (nota el `{SID}` en la ruta) y a **qué hora** se ejecutaron (la hora está dentro del valor de datos del registro).

### Prefetch de Windows

El prefetching es una técnica que permite a una computadora **obtener silenciosamente los recursos necesarios** para mostrar contenido al que un usuario **podría acceder en un futuro cercano** para que los recursos se puedan acceder más rápido.

El prefetch de Windows consiste en crear **cachés de los programas ejecutados** para poder cargarlos más rápido. Estas cachés se crean como archivos `.pf` dentro de la ruta: `C:\Windows\Prefetch`. Hay un límite de 128 archivos en XP/VISTA/WIN7 y 1024 archivos en Win8/Win10.

El nombre del archivo se crea como `{nombre_del_programa}-{hash}.pf` (el hash se basa en la ruta y argumentos del ejecutable). En W10 estos archivos están comprimidos. Cabe destacar que la mera presencia del archivo indica que **el programa fue ejecutado** en algún momento.

El archivo `C:\Windows\Prefetch\Layout.ini` contiene los **nombres de las carpetas de los archivos que se prefetean**. Este archivo contiene **información sobre el número de ejecuciones**, **fechas** de la ejecución y **archivos** **abiertos** por el programa.

Para inspeccionar estos archivos puedes usar la herramienta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** tiene el mismo objetivo que prefetch, **cargar programas más rápido** prediciendo qué se va a cargar a continuación. Sin embargo, no sustituye el servicio prefetch.\
Este servicio generará archivos de base de datos en `C:\Windows\Prefetch\Ag*.db`.

En estas bases de datos puedes encontrar el **nombre** del **programa**, **número** de **ejecuciones**, **archivos** **abiertos**, **volumen** **accedido**, **ruta** **completa**, **marcos de tiempo** y **marcas de tiempo**.

Puedes acceder a esta información utilizando la herramienta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitorea** los **recursos** **consumidos** **por un proceso**. Apareció en W8 y almacena los datos en una base de datos ESE ubicada en `C:\Windows\System32\sru\SRUDB.dat`.

Proporciona la siguiente información:

* AppID y Ruta
* Usuario que ejecutó el proceso
* Bytes enviados
* Bytes recibidos
* Interfaz de red
* Duración de la conexión
* Duración del proceso

Esta información se actualiza cada 60 minutos.

Puedes obtener los datos de este archivo utilizando la herramienta [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

El **AppCompatCache**, también conocido como **ShimCache**, forma parte de la **Base de Datos de Compatibilidad de Aplicaciones** desarrollada por **Microsoft** para abordar problemas de compatibilidad de aplicaciones. Este componente del sistema registra varios elementos de metadatos de archivos, que incluyen:

- Ruta completa del archivo
- Tamaño del archivo
- Hora de última modificación bajo **$Standard\_Information** (SI)
- Hora de última actualización del ShimCache
- Bandera de Ejecución del Proceso

Estos datos se almacenan en el registro en ubicaciones específicas según la versión del sistema operativo:

- Para XP, los datos se almacenan en `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` con una capacidad para 96 entradas.
- Para Server 2003, así como para las versiones de Windows 2008, 2012, 2016, 7, 8 y 10, la ruta de almacenamiento es `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, con capacidad para 512 y 1024 entradas, respectivamente.

Para analizar la información almacenada, se recomienda utilizar la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

El archivo **Amcache.hve** es esencialmente un registro que registra detalles sobre las aplicaciones que se han ejecutado en un sistema. Normalmente se encuentra en `C:\Windows\AppCompat\Programas\Amcache.hve`.

Este archivo es notable por almacenar registros de procesos ejecutados recientemente, incluidas las rutas a los archivos ejecutables y sus hashes SHA1. Esta información es invaluable para rastrear la actividad de las aplicaciones en un sistema.

Para extraer y analizar los datos de **Amcache.hve**, se puede utilizar la herramienta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). El siguiente comando es un ejemplo de cómo utilizar AmcacheParser para analizar el contenido del archivo **Amcache.hve** y mostrar los resultados en formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre los archivos CSV generados, el archivo `Entradas de archivos no asociados de Amcache` es particularmente notable debido a la rica información que proporciona sobre las entradas de archivos no asociados.

El archivo CSV más interesante generado es el `Entradas de archivos no asociados de Amcache`.

### RecentFileCache

Este artefacto solo se puede encontrar en W7 en `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` y contiene información sobre la ejecución reciente de algunos binarios.

Puedes utilizar la herramienta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analizar el archivo.

### Tareas programadas

Puedes extraerlas de `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` y leerlas como XML.

### Servicios

Puedes encontrarlos en el registro bajo `SYSTEM\ControlSet001\Services`. Puedes ver qué se va a ejecutar y cuándo.

### **Windows Store**

Las aplicaciones instaladas se pueden encontrar en `\ProgramData\Microsoft\Windows\AppRepository\`\
Este repositorio tiene un **registro** con **cada aplicación instalada** en el sistema dentro de la base de datos **`StateRepository-Machine.srd`**.

Dentro de la tabla de Aplicaciones de esta base de datos, es posible encontrar las columnas: "ID de la aplicación", "Número de paquete" y "Nombre para mostrar". Estas columnas tienen información sobre aplicaciones preinstaladas e instaladas y se puede determinar si algunas aplicaciones fueron desinstaladas porque los IDs de las aplicaciones instaladas deberían ser secuenciales.

También es posible **encontrar aplicaciones instaladas** en la ruta del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Y **desinstaladas** **aplicaciones** en: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos de Windows

La información que aparece en los eventos de Windows incluye:

* Qué sucedió
* Marca de tiempo (UTC + 0)
* Usuarios involucrados
* Equipos involucrados (nombre del host, IP)
* Activos accedidos (archivos, carpetas, impresoras, servicios)

Los registros se encuentran en `C:\Windows\System32\config` antes de Windows Vista y en `C:\Windows\System32\winevt\Logs` después de Windows Vista. Antes de Windows Vista, los registros de eventos estaban en formato binario y después, están en formato **XML** y utilizan la extensión **.evtx**.

La ubicación de los archivos de eventos se puede encontrar en el registro de SYSTEM en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Se pueden visualizar desde el Visor de eventos de Windows (**`eventvwr.msc`**) o con otras herramientas como [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprensión del Registro de eventos de seguridad de Windows

Los eventos de acceso se registran en el archivo de configuración de seguridad ubicado en `C:\Windows\System32\winevt\Security.evtx`. El tamaño de este archivo es ajustable y, cuando se alcanza su capacidad, los eventos antiguos son sobrescritos. Los eventos registrados incluyen inicios y cierres de sesión de usuarios, acciones de usuarios y cambios en la configuración de seguridad, así como acceso a activos compartidos, archivos y carpetas.

### IDs de eventos clave para la autenticación de usuarios:

* **ID de evento 4624**: Indica que un usuario se autenticó correctamente.
* **ID de evento 4625**: Indica un fallo de autenticación.
* **ID de eventos 4634/4647**: Representan eventos de cierre de sesión de usuarios.
* **ID de evento 4672**: Denota inicio de sesión con privilegios administrativos.

#### Subtipos dentro de los ID de eventos 4634/4647:

* **Interactivo (2)**: Inicio de sesión directo del usuario.
* **Red (3)**: Acceso a carpetas compartidas.
* **Lote (4)**: Ejecución de procesos por lotes.
* **Servicio (5)**: Inicio de servicios.
* **Proxy (6)**: Autenticación de proxy.
* **Desbloqueo (7)**: Desbloqueo de pantalla con contraseña.
* **Red en texto claro (8)**: Transmisión de contraseña en texto claro, a menudo desde IIS.
* **Nuevas credenciales (9)**: Uso de credenciales diferentes para el acceso.
* **Interactivo remoto (10)**: Inicio de sesión de escritorio remoto o servicios de terminal.
* **Interactivo en caché (11)**: Inicio de sesión con credenciales en caché sin contacto con el controlador de dominio.
* **Interactivo remoto en caché (12)**: Inicio de sesión remoto con credenciales en caché.
* **Desbloqueo en caché (13)**: Desbloqueo con credenciales en caché.

#### Códigos de estado y subestado para el ID de evento 4625:

* **0xC0000064**: El nombre de usuario no existe - Podría indicar un ataque de enumeración de nombres de usuario.
* **0xC000006A**: Nombre de usuario correcto pero contraseña incorrecta - Posible intento de adivinanza de contraseña o fuerza bruta.
* **0xC0000234**: Cuenta de usuario bloqueada - Puede seguir a un ataque de fuerza bruta que resulta en múltiples intentos de inicio de sesión fallidos.
* **0xC0000072**: Cuenta deshabilitada - Intentos no autorizados de acceder a cuentas deshabilitadas.
* **0xC000006F**: Inicio de sesión fuera del horario permitido - Indica intentos de acceso fuera del horario de inicio de sesión establecido, una posible señal de acceso no autorizado.
* **0xC0000070**: Violación de restricciones del lugar de trabajo - Podría ser un intento de inicio de sesión desde una ubicación no autorizada.
* **0xC0000193**: Expiración de cuenta - Intentos de acceso con cuentas de usuario vencidas.
* **0xC0000071**: Contraseña vencida - Intentos de inicio de sesión con contraseñas obsoletas.
* **0xC0000133**: Problemas de sincronización de tiempo - Grandes discrepancias de tiempo entre el cliente y el servidor pueden ser indicativas de ataques más sofisticados como pass-the-ticket.
* **0xC0000224**: Cambio obligatorio de contraseña requerido - Cambios obligatorios frecuentes podrían sugerir un intento de desestabilizar la seguridad de la cuenta.
* **0xC0000225**: Indica un error del sistema en lugar de un problema de seguridad.
* **0xC000015b**: Tipo de inicio de sesión denegado - Intento de acceso con un tipo de inicio de sesión no autorizado, como un usuario que intenta ejecutar un inicio de sesión de servicio.

#### EventoID 4616:

* **Cambio de hora**: Modificación de la hora del sistema, podría oscurecer la línea de tiempo de los eventos.

#### EventID 6005 y 6006:

* **Inicio y apagado del sistema**: El EventID 6005 indica el inicio del sistema, mientras que el EventID 6006 marca el apagado.

#### EventID 1102:

* **Eliminación de registro**: Los registros de seguridad se borran, lo cual suele ser una señal de encubrimiento de actividades ilícitas.

#### Eventos para el seguimiento de dispositivos USB:

* **20001 / 20003 / 10000**: Primera conexión del dispositivo USB.
* **10100**: Actualización del controlador USB.
* **EventoID 112**: Hora de inserción del dispositivo USB.

Para ejemplos prácticos sobre la simulación de estos tipos de inicio de sesión y oportunidades de robo de credenciales, consulta la guía detallada de [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Los detalles de los eventos, incluidos los códigos de estado y subestado, proporcionan más información sobre las causas de los eventos, especialmente notable en el Evento ID 4625.

### Recuperación de eventos de Windows

Para aumentar las posibilidades de recuperar eventos de Windows eliminados, es recomendable apagar directamente la computadora sospechosa desenchufándola. Se recomienda utilizar **Bulk\_extractor**, una herramienta de recuperación que especifica la extensión `.evtx`, para intentar recuperar dichos eventos.

### Identificación de ataques comunes a través de eventos de Windows

Para obtener una guía completa sobre cómo utilizar los ID de eventos de Windows para identificar ataques cibernéticos comunes, visita [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Ataques de fuerza bruta

Identificables por múltiples registros de EventID 4625, seguidos de un EventID 4624 si el ataque tiene éxito.

#### Cambio de hora

Registrado por el EventID 4616, los cambios en la hora del sistema pueden complicar el análisis forense.

#### Seguimiento de dispositivos USB

Los útiles EventIDs del sistema para el seguimiento de dispositivos USB incluyen 20001/20003/10000 para el uso inicial, 10100 para actualizaciones de controladores y EventID 112 de DeviceSetupManager para marcar los tiempos de inserción.
#### Eventos de Encendido del Sistema

El EventID 6005 indica el inicio del sistema, mientras que el EventID 6006 marca el apagado.

#### Eliminación de Registros

El EventID 1102 de Seguridad señala la eliminación de registros, un evento crítico para el análisis forense.
