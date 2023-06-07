# Artefactos de Windows

## Artefactos de Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Artefactos genéricos de Windows

### Notificaciones de Windows 10

En la ruta `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` se puede encontrar la base de datos `appdb.dat` (antes del aniversario de Windows) o `wpndatabase.db` (después del aniversario de Windows).

Dentro de esta base de datos SQLite, se puede encontrar la tabla `Notification` con todas las notificaciones (en formato XML) que pueden contener datos interesantes.

### Línea de tiempo

La línea de tiempo es una característica de Windows que proporciona un **historial cronológico** de las páginas web visitadas, los documentos editados y las aplicaciones ejecutadas.

La base de datos reside en la ruta `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Esta base de datos se puede abrir con una herramienta SQLite o con la herramienta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **que genera 2 archivos que se pueden abrir con la herramienta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Flujos de datos alternativos)

Los archivos descargados pueden contener la **Zona de identificación ADS** que indica **cómo** se **descargó** de la intranet, internet, etc. Algunos programas (como los navegadores) suelen poner incluso **más** **información** como la **URL** desde donde se descargó el archivo.

## **Copias de seguridad de archivos**

### Papelera de reciclaje

En Vista/Win7/Win8/Win10, la **Papelera de reciclaje** se puede encontrar en la carpeta **`$Recycle.bin`** en la raíz de la unidad (`C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta, se crean 2 archivos específicos:

* `$I{id}`: Información del archivo (fecha en que se eliminó}
* `$R{id}`: Contenido del archivo

![](<../../../.gitbook/assets/image (486).png>)

Teniendo estos archivos, se puede usar la herramienta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obtener la dirección original de los archivos eliminados y la fecha en que se eliminaron (usar `rifiuti-vista.exe` para Vista - Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Copias de sombra de volumen

Shadow Copy es una tecnología incluida en Microsoft Windows que puede crear **copias de seguridad** o instantáneas de archivos o volúmenes de computadora, incluso cuando están en uso.

Estas copias de seguridad generalmente se encuentran en `\System Volume Information` desde la raíz del sistema de archivos y el nombre está compuesto por **UIDs** que se muestran en la siguiente imagen:

![](<../../../.gitbook/assets/image (520).png>)

Montando la imagen forense con **ArsenalImageMounter**, la herramienta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) se puede usar para inspeccionar una copia de sombra e incluso **extraer los archivos** de las copias de seguridad de la copia de sombra.

![](<../../../.gitbook/assets/image (521).png>)

La entrada del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene los archivos y claves **que no se deben hacer copias de seguridad**:

![](<../../../.gitbook/assets/image (522).png>)

El registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene información de configuración sobre las `Copia de sombra de volumen`.

### Archivos de autoguardado de Office

Puede encontrar los archivos de autoguardado de Office en: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementos de shell

Un elemento de shell es un elemento que contiene información sobre cómo acceder a otro archivo.

### Documentos recientes (LNK)

Windows **crea automáticamente** estos **accesos directos** cuando el usuario **abre, usa o crea un archivo** en:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Cuando se crea una carpeta, también se crea un enlace a la carpeta, a la carpeta principal y a la carpeta abuela.

Estos archivos de enlace creados automáticamente **contienen información sobre el origen** como si es un **archivo** **o** una **carpeta**, **tiempos MAC** de ese archivo, **información de volumen** de dónde se almacena el archivo y **carpeta del archivo de destino**. Esta información puede ser útil para recuperar esos archivos en caso de que se eliminen.

Además, la **fecha de creación del archivo de enlace** es la primera **vez** que se **usó** el archivo original y la **fecha de modificación del archivo de enlace** es la **última vez** que se usó el archivo de origen.

Para inspeccionar estos archivos, puede usar [**LinkParser**](http://4discovery.com/our-tools/).

En esta herramienta encontrará **2 conjuntos** de marcas de tiempo:

* **Primer conjunto:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
* **Segundo conjunto:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

El primer conjunto de marcas de tiempo hace referencia a los **marcos de tiempo del archivo en sí**. El segundo conjunto hace referencia a los **marcos de tiempo del archivo vinculado**.

Puede obtener la misma información ejecutando la herramienta de línea de comandos de Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
En este caso, la información se guardará en un archivo CSV.

### Jumplists

Estas son las listas de archivos recientes que se indican por aplicación. Es la lista de **archivos recientes utilizados por una aplicación** a la que se puede acceder en cada aplicación. Pueden ser creados **automáticamente o personalizados**.

Las **jumplists** creadas automáticamente se almacenan en `C:\Users\{nombre de usuario}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Las jumplists se nombran siguiendo el formato `{id}.autmaticDestinations-ms` donde el ID inicial es el ID de la aplicación.

Las jumplists personalizadas se almacenan en `C:\Users\{nombre de usuario}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` y son creadas por la aplicación generalmente porque algo **importante** ha sucedido con el archivo (tal vez marcado como favorito).

El **tiempo de creación** de cualquier jumplist indica **la primera vez que se accedió al archivo** y el **tiempo modificado la última vez**.

Puede inspeccionar las jumplists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Tenga en cuenta que las marcas de tiempo proporcionadas por JumplistExplorer están relacionadas con el archivo de jumplist en sí_)

### Shellbags

[**Siga este enlace para aprender qué son las shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de USB de Windows

Es posible identificar que se ha utilizado un dispositivo USB gracias a la creación de:

* Carpeta Reciente de Windows
* Carpeta Reciente de Microsoft Office
* Jumplists

Tenga en cuenta que algunos archivos LNK en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

Los archivos en la carpeta WPDNSE son una copia de los originales, por lo que no sobrevivirán a un reinicio de la PC y el GUID se toma de una shellbag.

### Información del Registro

[Consulte esta página para aprender](interesting-windows-registry-keys.md#usb-information) qué claves del registro contienen información interesante sobre los dispositivos USB conectados.

### setupapi

Compruebe el archivo `C:\Windows\inf\setupapi.dev.log` para obtener las marcas de tiempo sobre cuándo se produjo la conexión USB (busque `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) se puede utilizar para obtener información sobre los dispositivos USB que se han conectado a una imagen.

![](<../../../.gitbook/assets/image (483).png>)

### Limpieza de Plug and Play

La tarea programada 'Limpieza de Plug and Play' es responsable de **eliminar** las versiones heredadas de los controladores. Parecería (basado en informes en línea) que también recoge **controladores que no se han utilizado en 30 días**, a pesar de que su descripción indica que "se mantendrá la versión más actual de cada paquete de controladores". Como tal, **los dispositivos extraíbles que no se hayan conectado durante 30 días pueden tener sus controladores eliminados**.

La tarea programada en sí se encuentra en ‘C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup’, y su contenido se muestra a continuación:

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

La tarea hace referencia a 'pnpclean.dll', que es responsable de realizar la actividad de limpieza. Además, vemos que el campo ‘UseUnifiedSchedulingEngine’ está configurado en ‘TRUE’, lo que especifica que el motor de programación de tareas genérico se utiliza para administrar la tarea. Los valores de ‘Period’ y ‘Deadline’ de 'P1M' y 'P2M' dentro
### BAM (Moderador de Actividad en Segundo Plano)

Puedes abrir el archivo `SYSTEM` con un editor de registro y dentro de la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` puedes encontrar la información sobre las **aplicaciones ejecutadas por cada usuario** (nota el `{SID}` en la ruta) y a **qué hora** fueron ejecutadas (la hora está dentro del valor de datos del registro).

### Prefetch de Windows

El prefetching es una técnica que permite a una computadora **buscar silenciosamente los recursos necesarios necesarios para mostrar contenido** que un usuario **podría acceder en un futuro cercano** para que los recursos puedan ser accedidos más rápidamente.

El prefetch de Windows consiste en crear **cachés de los programas ejecutados** para poder cargarlos más rápido. Estos cachés se crean como archivos `.pf` dentro de la ruta: `C:\Windows\Prefetch`. Hay un límite de 128 archivos en XP/VISTA/WIN7 y 1024 archivos en Win8/Win10.

El nombre del archivo se crea como `{nombre_del_programa}-{hash}.pf` (el hash se basa en la ruta y los argumentos del ejecutable). En W10 estos archivos están comprimidos. Ten en cuenta que la sola presencia del archivo indica que **el programa fue ejecutado** en algún momento.

El archivo `C:\Windows\Prefetch\Layout.ini` contiene los **nombres de las carpetas de los archivos que se prefetchearon**. Este archivo contiene **información sobre el número de ejecuciones**, **fechas** de la ejecución y **archivos** **abiertos** por el programa.

Para inspeccionar estos archivos puedes usar la herramienta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** tiene el mismo objetivo que prefetch, **cargar programas más rápido** prediciendo lo que se va a cargar a continuación. Sin embargo, no sustituye el servicio prefetch.\
Este servicio generará archivos de base de datos en `C:\Windows\Prefetch\Ag*.db`.

En estas bases de datos se puede encontrar el **nombre** del **programa**, **número** de **ejecuciones**, **archivos** **abiertos**, **volumen** **accedido**, **ruta** **completa**, **marcos de tiempo** y **marcas de tiempo**.

Puede acceder a esta información utilizando la herramienta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitorea** los **recursos** **consumidos** **por un proceso**. Apareció en W8 y almacena los datos en una base de datos ESE ubicada en `C:\Windows\System32\sru\SRUDB.dat`.

Proporciona la siguiente información:

* AppID y Path
* Usuario que ejecutó el proceso
* Bytes enviados
* Bytes recibidos
* Interfaz de red
* Duración de la conexión
* Duración del proceso

Esta información se actualiza cada 60 minutos.

Puede obtener la fecha de este archivo utilizando la herramienta [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**, también conocido como **AppCompatCache**, es un componente de la **Base de datos de compatibilidad de aplicaciones**, que fue creada por **Microsoft** y utilizada por el sistema operativo para identificar problemas de compatibilidad de aplicaciones.

La caché almacena varios metadatos de archivos dependiendo del sistema operativo, como:

* Ruta completa del archivo
* Tamaño del archivo
* **$Standard\_Information** (SI) Hora de última modificación
* Hora de última actualización de ShimCache
* Bandera de ejecución del proceso

Esta información se puede encontrar en el registro en:

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
  * XP (96 entradas)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
  * Server 2003 (512 entradas)
  * 2008/2012/2016 Win7/Win8/Win10 (1024 entradas)

Puede utilizar la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) para analizar esta información.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

El archivo **Amcache.hve** es un archivo de registro que almacena la información de las aplicaciones ejecutadas. Se encuentra en `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** registra los procesos recientes que se ejecutaron y lista la ruta de los archivos que se ejecutan, lo que luego se puede utilizar para encontrar el programa ejecutado. También registra el SHA1 del programa.

Puede analizar esta información con la herramienta [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
El archivo CVS más interesante generado es el de `Entradas de archivos no asociados de Amcache`.

### RecentFileCache

Este artefacto solo se puede encontrar en W7 en `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` y contiene información sobre la ejecución reciente de algunos binarios.

Puede usar la herramienta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analizar el archivo.

### Tareas programadas

Puede extraerlas de `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` y leerlas como XML.

### Servicios

Puede encontrarlos en el registro en `SYSTEM\ControlSet001\Services`. Puede ver qué se va a ejecutar y cuándo.

### **Windows Store**

Las aplicaciones instaladas se pueden encontrar en `\ProgramData\Microsoft\Windows\AppRepository\`. Este repositorio tiene un **registro** con **cada aplicación instalada** en el sistema dentro de la base de datos **`StateRepository-Machine.srd`**.

Dentro de la tabla de aplicaciones de esta base de datos, es posible encontrar las columnas: "ID de aplicación", "Número de paquete" y "Nombre para mostrar". Estas columnas tienen información sobre aplicaciones preinstaladas e instaladas y se puede encontrar si algunas aplicaciones se desinstalaron porque los ID de las aplicaciones instaladas deberían ser secuenciales.

También es posible **encontrar aplicaciones instaladas** dentro de la ruta del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Y **aplicaciones desinstaladas** en: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos de Windows

La información que aparece dentro de los eventos de Windows es:

* Qué sucedió
* Marca de tiempo (UTC + 0)
* Usuarios involucrados
* Hosts involucrados (nombre de host, IP)
* Activos accedidos (archivos, carpetas, impresoras, servicios)

Los registros se encuentran en `C:\Windows\System32\config` antes de Windows Vista y en `C:\Windows\System32\winevt\Logs` después de Windows Vista. Antes de Windows Vista, los registros de eventos estaban en formato binario y después de eso, están en formato **XML** y usan la extensión **.evtx**.

La ubicación de los archivos de eventos se puede encontrar en el registro del sistema en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Se pueden visualizar desde el Visor de eventos de Windows (**`eventvwr.msc`**) o con otras herramientas como [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

### Seguridad

Esto registra los eventos de acceso y proporciona información sobre la configuración de seguridad que se puede encontrar en `C:\Windows\System32\winevt\Security.evtx`.

El **tamaño máximo** del archivo de eventos es configurable y comenzará a sobrescribir eventos antiguos cuando se alcance el tamaño máximo.

Eventos que se registran como:

* Inicio de sesión/cierre de sesión
* Acciones del usuario
* Acceso a archivos, carpetas y activos compartidos
* Modificación de la configuración de seguridad

Eventos relacionados con la autenticación del usuario:

| EventID   | Descripción                  |
| --------- | ---------------------------- |
| 4624      | Autenticación exitosa        |
| 4625      | Error de autenticación       |
| 4634/4647 | Cierre de sesión             |
| 4672      | Inicio de sesión con permisos de administrador |

Dentro del EventID 4634/4647 hay subtipos interesantes:

* **2 (interactivo)**: El inicio de sesión fue interactivo usando el teclado o software como VNC o `PSexec -U-`
* **3 (red)**: Conexión a una carpeta compartida
* **4 (lote)**: Proceso ejecutado
* **5 (servicio)**: Servicio iniciado por el Administrador de control de servicios
* **6 (proxy):** Inicio de sesión de proxy
* **7 (desbloqueo)**: Pantalla desbloqueada usando contraseña
* **8 (texto sin formato de red)**: Usuario autenticado enviando contraseñas en texto sin formato. Este evento solía venir de IIS
* **9 (nuevas credenciales)**: Se genera cuando se usa el comando `RunAs` o el usuario accede a un servicio de red con diferentes credenciales.
* **10 (interactivo remoto)**: Autenticación a través de Terminal Services o RDP
* **11 (caché interactivo)**: Acceso utilizando las últimas credenciales en caché porque no fue posible contactar al controlador de dominio
* **12 (caché interactivo remoto)**: Inicio de sesión remoto con credenciales en caché (una combinación de 10 y 11).
* **13 (desbloqueo en caché)**: Desbloquear una máquina bloqueada con credenciales en caché.

En esta publicación, puede encontrar cómo imitar todos estos tipos de inicio de sesión y en cuáles de ellos podrá volcar credenciales desde la memoria: [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

La información de estado y subestado de los eventos puede indicar más detalles sobre las causas del evento. Por ejemplo, eche un vistazo a los siguientes códigos de estado y subestado del Evento ID 4625:

![](<../../../.gitbook/assets/image (455).png>)

### Recuperación de eventos de Windows

Es altamente recomendable apagar la PC sospechosa **desenchufándola** para maximizar la probabilidad de recuperar los eventos de Windows. En caso de que se hayan eliminado, una herramienta que puede ser útil para intentar recuperarlos es [**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) indicando la extensión **evtx**.

## Identificación de ataques comunes con eventos de Windows

### Ataque de fuerza bruta

Un ataque de fuerza bruta se puede identificar fácilmente porque aparecerán **varios EventIDs 4625**. Si el ataque fue **exitoso**, después de los EventIDs 4625, **aparecerá un EventID 4624**.

### Cambio de hora

Esto es terrible para el equipo forense ya que todas las marcas de tiempo se modificarán. Este evento se registra con el EventID 4616 dentro del registro de eventos de seguridad.

### Dispositivos USB

Los siguientes EventIDs del sistema son útiles:

* 20001 / 20003 / 10000: Primera vez que se usó
* 10100: Actualización del controlador

El EventID 112 de DeviceSetupManager contiene la marca de tiempo de cada dispositivo USB insertado.

### Encendido / Apagado

El ID 6005 del servicio "Registro de eventos" indica que la PC se encendió. El ID 6006 indica que se apagó.

### Eliminación de registros

El EventID 1102 de seguridad indica que se eliminaron los registros.
