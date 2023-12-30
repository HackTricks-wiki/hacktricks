# Artefactos de Windows

## Artefactos de Windows

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Artefactos Genéricos de Windows

### Notificaciones de Windows 10

En la ruta `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` puedes encontrar la base de datos `appdb.dat` (antes del aniversario de Windows) o `wpndatabase.db` (después del aniversario de Windows).

Dentro de esta base de datos SQLite, puedes encontrar la tabla `Notification` con todas las notificaciones (en formato XML) que pueden contener datos interesantes.

### Timeline

Timeline es una característica de Windows que proporciona un **historial cronológico** de páginas web visitadas, documentos editados y aplicaciones ejecutadas.

La base de datos se encuentra en la ruta `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Esta base de datos se puede abrir con una herramienta SQLite o con la herramienta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **que genera 2 archivos que se pueden abrir con la herramienta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Los archivos descargados pueden contener el **ADS Zone.Identifier** que indica **cómo** fue **descargado** de la intranet, internet, etc. Algunos programas (como navegadores) suelen poner incluso **más** **información** como la **URL** de donde se descargó el archivo.

## **Copias de Seguridad de Archivos**

### Papelera de Reciclaje

En Vista/Win7/Win8/Win10 la **Papelera de Reciclaje** se puede encontrar en la carpeta **`$Recycle.bin`** en la raíz del disco (`C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta se crean 2 archivos específicos:

* `$I{id}`: Información del archivo (fecha en que fue eliminado)
* `$R{id}`: Contenido del archivo

![](<../../../.gitbook/assets/image (486).png>)

Teniendo estos archivos puedes usar la herramienta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obtener la dirección original de los archivos eliminados y la fecha en que se eliminaron (usa `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
### Copias de sombra de volumen

Shadow Copy es una tecnología incluida en Microsoft Windows que puede crear **copias de seguridad** o instantáneas de archivos de computadora o volúmenes, incluso cuando están en uso.

Estas copias de seguridad generalmente se encuentran en `\System Volume Information` desde la raíz del sistema de archivos y el nombre está compuesto por **UIDs** mostrados en la siguiente imagen:

![](<../../../.gitbook/assets/image (520).png>)

Montando la imagen forense con **ArsenalImageMounter**, la herramienta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) se puede utilizar para inspeccionar una copia de sombra e incluso **extraer los archivos** de las copias de seguridad de la copia de sombra.

![](<../../../.gitbook/assets/image (521).png>)

La entrada del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene los archivos y claves **para no respaldar**:

![](<../../../.gitbook/assets/image (522).png>)

El registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene información de configuración sobre las `Copias de sombra de volumen`.

### Archivos AutoGuardados de Office

Puedes encontrar los archivos autoguardados de office en: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementos de Shell

Un elemento de shell es un ítem que contiene información sobre cómo acceder a otro archivo.

### Documentos Recientes (LNK)

Windows **crea automáticamente** estos **accesos directos** cuando el usuario **abre, usa o crea un archivo** en:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Cuando se crea una carpeta, también se crea un enlace a la carpeta, a la carpeta padre y a la carpeta abuela.

Estos archivos de enlace creados automáticamente **contienen información sobre el origen** como si es un **archivo** **o** una **carpeta**, **tiempos MAC** de ese archivo, **información del volumen** de dónde está almacenado el archivo y **carpeta del archivo objetivo**. Esta información puede ser útil para recuperar esos archivos en caso de que se hayan eliminado.

Además, la **fecha de creación del archivo de enlace** es la primera **vez** que el archivo original fue **utilizado** y la **fecha de modificación** del archivo de enlace es la **última vez** que se utilizó el archivo de origen.

Para inspeccionar estos archivos puedes usar [**LinkParser**](http://4discovery.com/our-tools/).

En esta herramienta encontrarás **2 conjuntos** de marcas de tiempo:

* **Primer Conjunto:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Segundo Conjunto:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

El primer conjunto de marcas de tiempo hace referencia a las **marcas de tiempo del propio archivo**. El segundo conjunto hace referencia a las **marcas de tiempo del archivo vinculado**.

Puedes obtener la misma información ejecutando la herramienta CLI de Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
En este caso, la información se guardará dentro de un archivo CSV.

### Jumplists

Estas son los archivos recientes que se indican por aplicación. Es la lista de **archivos recientes utilizados por una aplicación** a la que puedes acceder en cada aplicación. Pueden ser creados **automáticamente o ser personalizados**.

Las **jumplists** creadas automáticamente se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Las jumplists se nombran siguiendo el formato `{id}.autmaticDestinations-ms` donde el ID inicial es el ID de la aplicación.

Las jumplists personalizadas se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` y son creadas por la aplicación generalmente porque algo **importante** ha sucedido con el archivo (quizás marcado como favorito)

El **tiempo de creación** de cualquier jumplist indica **la primera vez que se accedió al archivo** y el **tiempo modificado la última vez**.

Puedes inspeccionar las jumplists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Nota que las marcas de tiempo proporcionadas por JumplistExplorer están relacionadas con el archivo jumplist en sí_)

### Shellbags

[**Sigue este enlace para aprender qué son los shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de USBs en Windows

Es posible identificar que se utilizó un dispositivo USB gracias a la creación de:

* Carpeta Reciente de Windows
* Carpeta Reciente de Microsoft Office
* Jumplists

Nota que algunos archivos LNK en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

Los archivos en la carpeta WPDNSE son una copia de los originales, entonces no sobrevivirán un reinicio de la PC y el GUID se toma de un shellbag.

### Información del Registro

[Consulta esta página para aprender](interesting-windows-registry-keys.md#usb-information) qué claves del registro contienen información interesante sobre dispositivos USB conectados.

### setupapi

Revisa el archivo `C:\Windows\inf\setupapi.dev.log` para obtener las marcas de tiempo sobre cuándo se produjo la conexión USB (busca `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) se puede utilizar para obtener información sobre los dispositivos USB que se han conectado a una imagen.

![](<../../../.gitbook/assets/image (483).png>)

### Limpieza de Plug and Play

La tarea programada 'Limpieza de Plug and Play' es responsable de **limpiar** versiones antiguas de controladores. Parece (según informes en línea) que también recoge **controladores que no se han utilizado en 30 días**, a pesar de que su descripción indica que "se mantendrá la versión más actual de cada paquete de controladores". Como tal, **los dispositivos extraíbles que no se han conectado durante 30 días pueden tener sus controladores eliminados**.

La tarea programada en sí se encuentra en 'C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup', y su contenido se muestra a continuación:

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

La tarea hace referencia a 'pnpclean.dll' que es responsable de realizar la actividad de limpieza, además vemos que el campo ‘UseUnifiedSchedulingEngine’ está configurado como ‘TRUE’, lo que especifica que se utiliza el motor de programación de tareas genérico para gestionar la tarea. Los valores ‘Period’ y ‘Deadline’ de 'P1M' y 'P2M' dentro de ‘MaintenanceSettings’ instruyen al Programador de Tareas para ejecutar la tarea una vez al mes durante el mantenimiento Automático regular y si falla durante 2 meses consecutivos, para comenzar a intentar la tarea durante el mantenimiento Automático de emergencia. **Esta sección fue copiada de** [**aquí**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**.**

## Correos Electrónicos

Los correos electrónicos contienen **2 partes interesantes: Los encabezados y el contenido** del correo electrónico. En los **encabezados** puedes encontrar información como:

* **Quién** envió los correos (dirección de correo electrónico, IP, servidores de correo que han redirigido el correo)
* **Cuándo** se envió el correo electrónico

Además, dentro de los encabezados `References` y `In-Reply-To` puedes encontrar el ID de los mensajes:

![](<../../../.gitbook/assets/image (484).png>)

### Aplicación de Correo de Windows

Esta aplicación guarda correos electrónicos en HTML o texto. Puedes encontrar los correos dentro de subcarpetas en `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Los correos se guardan con la extensión `.dat`.

La **metadatos** de los correos y los **contactos** se pueden encontrar dentro de la **base de datos EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia la extensión** del archivo de `.vol` a `.edb` y puedes usar la herramienta [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) para abrirlo. Dentro de la tabla `Message` puedes ver los correos.

### Microsoft Outlook

Cuando se utilizan servidores Exchange o clientes Outlook, van a haber algunos encabezados MAPI:

* `Mapi-Client-Submit-Time`: Hora del sistema cuando se envió el correo electrónico
* `Mapi-Conversation-Index`: Número de mensajes hijos del hilo y marca de tiempo de cada mensaje del hilo
* `Mapi-Entry-ID`: Identificador del mensaje.
* `Mappi-Message-Flags` y `Pr_last_Verb-Executed`: Información sobre el cliente MAPI (mensaje leído? no leído? respondido? redirigido? fuera de la oficina?)

En el cliente Microsoft Outlook, todos los mensajes enviados/recibidos, datos de contactos y datos del calendario se almacenan en un archivo PST en:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

La ruta del registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica el archivo que se está utilizando.

Puedes abrir el archivo PST usando la herramienta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

Cuando Microsoft Outlook está configurado **usando** **IMAP** o utilizando un servidor **Exchange**, genera un archivo **OST** que almacena casi la misma información que el archivo PST. Mantiene el archivo sincronizado con el servidor durante **los últimos 12 meses**, con un **tamaño máximo de archivo de 50GB** y en la **misma carpeta donde se guarda el archivo PST**. Puedes inspeccionar este archivo usando [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recuperación de Adjuntos

Puedes ser capaz de encontrarlos en la carpeta:

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird** almacena la información en **archivos MBOX** en la carpeta `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`

## Miniaturas

Cuando un usuario accede a una carpeta y la organiza usando miniaturas, entonces se crea un archivo `thumbs.db`. Esta base de datos **almacena las miniaturas de las imágenes** de la carpeta incluso si se eliminan. En WinXP y Win 8-8.1 este archivo se crea automáticamente. En Win7/Win10, se crea automáticamente si se accede a través de una ruta UNC (\IP\carpeta...).

Es posible leer este archivo con la herramienta [**Thumbsviewer**](https://thumbsviewer.github.io).

### Thumbcache

A partir de Windows Vista, **las vistas previas de miniaturas se almacenan en una ubicación centralizada en el sistema**. Esto proporciona al sistema acceso a imágenes independientemente de su ubicación y aborda problemas con la localidad de los archivos Thumbs.db. La caché se almacena en **`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`** como varios archivos con la etiqueta **thumbcache\_xxx.db** (numerados por tamaño); así como un índice utilizado para encontrar miniaturas en cada base de datos de tamaño.

* Thumbcache\_32.db -> pequeño
* Thumbcache\_96.db -> mediano
* Thumbcache\_256.db -> grande
* Thumbcache\_1024.db -> extra grande

Puedes leer este archivo usando [**ThumbCache Viewer**](https://thumbcacheviewer.github.io).

## Registro de Windows

El Registro de Windows contiene mucha **información** sobre el **sistema y las acciones de los usuarios**.

Los archivos que contienen el registro se encuentran en:

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

Desde Windows Vista y Windows 2008 Server en adelante hay algunas copias de seguridad de los archivos del registro `HKEY_LOCAL_MACHINE` en **`%Windir%\System32\Config\RegBack\`**.

También desde estas versiones, se crea el archivo de registro **`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`** guardando información sobre ejecuciones de programas.

### Herramientas

Algunas herramientas son útiles para analizar los archivos del registro:

* **Editor del Registro**: Está instalado en Windows. Es una GUI para navegar a través del registro de Windows de la sesión actual.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite cargar el archivo del registro y navegar a través de ellos con una GUI. También contiene Marcadores que resaltan claves con información interesante.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): De nuevo, tiene una GUI que permite navegar a través del registro cargado y también contiene plugins que resaltan información interesante dentro del registro cargado.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Otra aplicación GUI capaz de extraer la información importante del registro cargado.

### Recuperación de Elementos Eliminados

Cuando se elimina una clave, se marca como tal, pero hasta que no se necesite el espacio que ocupa, no se eliminará. Por lo tanto, utilizando herramientas como **Registry Explorer** es posible recuperar estas claves eliminadas.

### Última Hora de Escritura

Cada Clave-Valor contiene una **marca de tiempo** que indica la última vez que fue modificada.

### SAM

El archivo/colmena **SAM** contiene los **usuarios, grupos y hashes de contraseñas de usuarios** del sistema.

En `SAM\Domains\Account\Users` puedes obtener el nombre de usuario, el RID, último inicio de sesión, último inicio de sesión fallido, contador de inicio de sesión, política de contraseñas y cuándo se creó la cuenta. Para obtener los **hashes** también **necesitas** el archivo/colmena **SYSTEM**.

### Entradas interesantes en el Registro de Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programas Ejecutados

### Procesos Básicos de Windows

En la siguiente página puedes aprender sobre los procesos básicos de Windows para detectar comportamientos sospechosos:

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### APPs Recientes de Windows

Dentro del registro `NTUSER.DAT` en la ruta `Software\Microsoft\Current Version\Search\RecentApps` puedes encontrar subclaves con información sobre la **aplicación ejecutada**, **última vez** que se ejecutó y **número de veces** que se lanzó.

### BAM (Moderador de Actividad en Segundo Plano)

Puedes abrir el archivo `SYSTEM` con un editor del registro y dentro de la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` puedes encontrar la información sobre las **aplicaciones ejecutadas por cada usuario** (nota el `{SID}` en la ruta) y en **qué momento** fueron ejecutadas (el tiempo está dentro del valor de Datos del registro).

### Prefetch de Windows

El prefetching es una técnica que permite a una computadora obtener silenciosamente **los recursos necesarios para mostrar contenido** que un usuario **podría acceder en un futuro cercano** para que los recursos se puedan acceder más rápidamente.

El prefetch de Windows consiste en crear **cachés de los programas ejecutados** para poder cargarlos más rápido. Estos cachés se crean como archivos `.pf` dentro de la ruta: `C:\Windows\Prefetch`. Hay un límite de 128 archivos en XP/VISTA/WIN7 y 1024 archivos en Win8/Win10.

El nombre del archivo se crea como `{program_name}-{hash}.pf` (el hash se basa en la ruta y argumentos del ejecutable). En W10 estos archivos están comprimidos. Ten en cuenta que la sola presencia del archivo indica que **el programa fue ejecutado** en algún momento.

El archivo `C:\Windows\Prefetch\Layout.ini` contiene los **nombres de las carpetas de los archivos que se prefetchan**. Este archivo contiene **información sobre el número de ejecuciones**, **fechas** de la ejecución y **archivos** **abiertos** por el programa.

Para inspeccionar estos archivos puedes usar la herramienta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
```markdown
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** tiene el mismo objetivo que prefetch, **cargar programas más rápido** al predecir lo que se cargará a continuación. Sin embargo, no sustituye al servicio de prefetch.
Este servicio generará archivos de base de datos en `C:\Windows\Prefetch\Ag*.db`.

En estas bases de datos puedes encontrar el **nombre** del **programa**, **número** de **ejecuciones**, **archivos** **abiertos**, **volumen** **accedido**, **ruta** **completa**, **intervalos de tiempo** y **marcas de tiempo**.

Puedes acceder a esta información utilizando la herramienta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitorea** los **recursos** **consumidos** **por un proceso**. Apareció en W8 y almacena los datos en una base de datos ESE ubicada en `C:\Windows\System32\sru\SRUDB.dat`.

Proporciona la siguiente información:

* AppID y Ruta
* Usuario que ejecutó el proceso
* Bytes Enviados
* Bytes Recibidos
* Interfaz de Red
* Duración de la conexión
* Duración del proceso

Esta información se actualiza cada 60 minutos.

Puedes obtener los datos de este archivo utilizando la herramienta [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**, también conocido como **AppCompatCache**, es un componente de la **Base de Datos de Compatibilidad de Aplicaciones**, que fue creada por **Microsoft** y es utilizada por el sistema operativo para identificar problemas de compatibilidad de aplicaciones.

La caché almacena varios metadatos de archivos dependiendo del sistema operativo, tales como:

* Ruta completa del archivo
* Tamaño del archivo
* **$Standard\_Information** (SI) Última modificación
* Última actualización de ShimCache
* Bandera de ejecución de proceso

Esta información se puede encontrar en el registro en:

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 entradas)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 entradas)
* 2008/2012/2016 Win7/Win8/Win10 (1024 entradas)

Puedes utilizar la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) para analizar esta información.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

El archivo **Amcache.hve** es un archivo de registro que almacena la información de las aplicaciones ejecutadas. Se encuentra en `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** registra los procesos recientes que se han ejecutado y lista la ruta de los archivos que se ejecutan, lo cual puede ser utilizado para encontrar el programa ejecutado. También registra el SHA1 del programa.

Puedes analizar esta información con la herramienta [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
El archivo CVS más interesante generado es `Amcache_Unassociated file entries`.

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

Dentro de la tabla de aplicaciones de esta base de datos, es posible encontrar las columnas: "Application ID", "PackageNumber" y "Display Name". Estas columnas tienen información sobre aplicaciones preinstaladas e instaladas y se puede saber si algunas aplicaciones fueron desinstaladas porque los ID de las aplicaciones instaladas deberían ser secuenciales.

También es posible **encontrar aplicaciones instaladas** dentro de la ruta del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Y **aplicaciones desinstaladas** en: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos de Windows

La información que aparece dentro de los eventos de Windows es:

* Qué sucedió
* Marca de tiempo (UTC + 0)
* Usuarios involucrados
* Hosts involucrados (nombre de host, IP)
* Activos accedidos (archivos, carpetas, impresoras, servicios)

Los registros se encuentran en `C:\Windows\System32\config` antes de Windows Vista y en `C:\Windows\System32\winevt\Logs` después de Windows Vista. Antes de Windows Vista, los registros de eventos estaban en formato binario y después, están en **formato XML** y usan la extensión **.evtx**.

La ubicación de los archivos de eventos se puede encontrar en el registro SYSTEM en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Se pueden visualizar desde el Visor de Eventos de Windows (**`eventvwr.msc`**) o con otras herramientas como [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

### Seguridad

Este registra los eventos de acceso y proporciona información sobre la configuración de seguridad que se puede encontrar en `C:\Windows\System32\winevt\Security.evtx`.

El **tamaño máximo** del archivo de eventos es configurable, y comenzará a sobrescribir eventos antiguos cuando se alcance el tamaño máximo.

Eventos que se registran como:

* Inicio/Cierre de sesión
* Acciones del usuario
* Acceso a archivos, carpetas y activos compartidos
* Modificación de la configuración de seguridad

Eventos relacionados con la autenticación de usuarios:

| EventID   | Descripción                  |
| --------- | ---------------------------- |
| 4624      | Autenticación exitosa        |
| 4625      | Error de autenticación       |
| 4634/4647 | Cierre de sesión             |
| 4672      | Inicio de sesión con permisos de administrador |

Dentro del EventID 4634/4647 hay subtipos interesantes:

* **2 (interactivo)**: El inicio de sesión fue interactivo usando el teclado o software como VNC o `PSexec -U-`
* **3 (red)**: Conexión a una carpeta compartida
* **4 (Batch)**: Proceso ejecutado
* **5 (servicio)**: Servicio iniciado por el Administrador de Control de Servicios
* **6 (proxy):** Inicio de sesión Proxy
* **7 (Desbloqueo)**: Pantalla desbloqueada usando contraseña
* **8 (texto claro de red)**: Usuario autenticado enviando contraseñas en texto claro. Este evento solía provenir del IIS
* **9 (nuevas credenciales)**: Se genera cuando se usa el comando `RunAs` o el usuario accede a un servicio de red con diferentes credenciales.
* **10 (interactivo remoto)**: Autenticación a través de Servicios de Terminal o RDP
* **11 (interactivo de caché)**: Acceso usando las últimas credenciales en caché porque no fue posible contactar al controlador de dominio
* **12 (interactivo remoto de caché)**: Inicio de sesión remoto con credenciales en caché (una combinación de 10 y 11).
* **13 (desbloqueo de caché)**: Desbloqueo de una máquina bloqueada con credenciales en caché.

En este post, puedes encontrar cómo imitar todos estos tipos de inicio de sesión y en cuáles podrás volcar credenciales de la memoria: [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

La información de Estado y subestado de los eventos puede indicar más detalles sobre las causas del evento. Por ejemplo, echa un vistazo a los siguientes Códigos de Estado y Subestado del Evento ID 4625:

![](<../../../.gitbook/assets/image (455).png>)

### Recuperación de Eventos de Windows

Es altamente recomendable apagar la PC sospechosa **desconectándola** para maximizar la probabilidad de recuperar los Eventos de Windows. En caso de que hayan sido eliminados, una herramienta que puede ser útil para intentar recuperarlos es [**Bulk_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) indicando la extensión **evtx**.

## Identificación de Ataques Comunes con Eventos de Windows

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### Ataque de Fuerza Bruta

Un ataque de fuerza bruta se puede identificar fácilmente porque **aparecerán varios EventIDs 4625**. Si el ataque fue **exitoso**, después de los EventIDs 4625, **aparecerá un EventID 4624**.

### Cambio de Hora

Esto es terrible para el equipo de forenses ya que se modificarán todas las marcas de tiempo. Este evento se registra por el EventID 4616 dentro del registro de eventos de Seguridad.

### Dispositivos USB

Los siguientes EventIDs del Sistema son útiles:

* 20001 / 20003 / 10000: Primera vez que se usó
* 10100: Actualización de controlador

El EventID 112 de DeviceSetupManager contiene la marca de tiempo de cada dispositivo USB insertado.

### Apagado / Encendido

El ID 6005 del servicio "Event Log" indica que la PC se encendió. El ID 6006 indica que se apagó.

### Eliminación de Registros

El EventID 1102 de Seguridad indica que los registros fueron eliminados.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
