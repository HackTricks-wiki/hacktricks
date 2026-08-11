# Artefactos de Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos genéricos de Windows

### Notificaciones de Windows 10

La base de datos de notificaciones por usuario se encuentra en `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (por ejemplo, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Las primeras versiones de Windows 10 usaban `appdb.dat`; la Anniversary Update (1607) introdujo `wpndatabase.db`. La base de datos SQLite incluye una tabla `Notification` con payloads de notificaciones y campos de tiempo, aunque la retención y los datos disponibles varían según la versión y la política de limpieza.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline es una función de historial de actividad que puede contener registros de aplicaciones compatibles, documentos y otras actividades del usuario; su cobertura depende de la aplicación y de la versión de Windows.<sup>[[4]](#references)</sup>

La base de datos se encuentra en `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Puede abrirse con SQLite o analizarse con [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), cuya salida puede revisarse con [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Los archivos descargados desde fuera del límite de confianza local pueden contener el **flujo de datos alternativo `Zone.Identifier`**, que registra información de zona y puede incluir metadatos de origen, como una URL. Su presencia y sus campos dependen del productor y de la política del sistema.<sup>[[6]](#references)</sup>

## **Copias de seguridad de archivos**

### Papelera de reciclaje

En Vista y versiones posteriores, la **Papelera de reciclaje** se encuentra en la carpeta **`$Recycle.bin`** en la raíz de la unidad (por ejemplo, `C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta, se crean 2 archivos específicos:

- `$I{id}`: Información del archivo, incluida la hora de eliminación y la ruta original
- `$R{id}`: Contenido del archivo

![Copias de seguridad de archivos - Papelera de reciclaje: $R{id}: Contenido del archivo](<../../../images/image (1029).png>)

Con estos archivos, puedes usar [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) para extraer la ruta original y la hora de eliminación (usa la versión adecuada para la versión de Windows objetivo).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) puede crear copias shadow de los volúmenes en un momento determinado mientras los archivos están en uso; una copia shadow no sustituye a una imagen forense.<sup>[[8]](#references)</sup>

Los metadatos de la copia normalmente están asociados con `\System Volume Information` en la raíz del volumen, con identificadores que varían según el sistema:

![Recycle Bin - Volume Shadow Copies: Estas copias de seguridad suelen encontrarse en System Volume Information, en la raíz del sistema de archivos, y el nombre está compuesto por UIDs mostrados en el...](<../../../images/image (94).png>)

Después de montar una imagen con un forensic mounter adecuado, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) puede enumerar las instantáneas VSS disponibles y explorar o copiar archivos desde ellas.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Al montar la imagen forense con ArsenalImageMounter, la herramienta ShadowCopyView puede utilizarse para inspeccionar una copia shadow e incluso extraer los archivos...](<../../../images/image (576).png>)

La configuración del registry writer de VSS incluye `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, que puede especificar archivos y claves excluidos de la copia de seguridad:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: La entrada del registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contiene los archivos y claves que no deben incluirse en la copia de seguridad](<../../../images/image (254).png>)

La clave `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene la configuración del servicio VSS.<sup>[[8]](#references)</sup>

### Archivos AutoSaved de Office

Las ubicaciones de AutoRecover varían según la aplicación de Office, la versión y la configuración. Para Word, Microsoft documenta `%APPDATA%\Microsoft\Word` como la ubicación predeterminada; comprueba la configuración de la aplicación para conocer la ruta activa.<sup>[[12]](#references)</sup>

## Elementos de Shell

Un elemento de shell contiene información sobre cómo acceder a otro archivo.

### Documentos recientes (LNK)

Windows suele crear accesos directos a elementos recientes cuando un usuario abre o accede de cualquier otra forma a un elemento:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

El acceso a una carpeta también puede crear enlaces para la carpeta y las carpetas padre relacionadas.

Estos archivos de enlace pueden contener el tipo de destino, las horas MAC del destino, información del volumen y la ruta del destino. Esos metadatos pueden ayudar a identificar un destino eliminado, pero el artefacto no constituye por sí mismo una prueba de que el destino haya sido abierto por un usuario concreto.<sup>[[13]](#references)[[14]](#references)</sup>

Las marcas de tiempo del sistema de archivos del propio LNK y las marcas de tiempo del destino insertadas en él son distintas. No interpretes la creación del enlace como el primer uso ni la modificación del enlace como el último uso sin artefactos que lo corroboren; el formato almacena por separado las marcas de tiempo del destino y las del archivo de enlace.<sup>[[13]](#references)[[14]](#references)</sup>

El enlace existente a [**LinkParser**](http://4discovery.com/our-tools/) se conserva como opción histórica, pero su documentación no estaba disponible durante la revisión. Para utilizar un parser documentado de línea de comandos, usa [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Estas herramientas suelen mostrar dos conjuntos de marcas de tiempo:

- **Marcas de tiempo del destino:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Marcas de tiempo del archivo de enlace:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

El primer conjunto se refiere al destino; el segundo, al propio archivo LNK. Interpreta ambos conjuntos teniendo en cuenta la documentación del parser y el contexto del sistema de archivos.<sup>[[14]](#references)[[15]](#references)</sup>

Puedes obtener la misma información ejecutando la herramienta CLI de Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
En este caso, la información se guardará en un archivo CSV.

### Jumplists

Las Jump Lists son listas por aplicación de elementos recientes o específicos de tareas, y pueden ser automáticas o personalizadas.<sup>[[13]](#references)</sup>

Las Jump Lists automáticas se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` y utilizan nombres como `{id}.automaticDestinations-ms`, donde el ID identifica la aplicación.

Las Jump Lists personalizadas se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; la aplicación controla las entradas de tareas o elementos que crea.

Las fechas de creación y modificación del sistema de archivos describen el archivo de la Jump List, no necesariamente el primer y último acceso a cada destino listado. Correlaciona las entradas analizadas con las marcas de tiempo del archivo y otros artefactos.<sup>[[13]](#references)</sup>

Puedes inspeccionar las Jump Lists utilizando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Documentos recientes (LNK) - Jumplists: Puedes inspeccionar las jumplists utilizando JumplistExplorer](<../../../images/image (168).png>)

(_Ten en cuenta que las marcas de tiempo proporcionadas por JumplistExplorer están relacionadas con el archivo de la jumplist_)

### Shellbags

[**Sigue este enlace para saber qué son los shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de dispositivos USB en Windows

El uso de USB puede corroborarse en ocasiones mediante artefactos creados cuando se accede a archivos desde medios extraíbles, incluidos:

- Carpeta Recent de Windows
- Carpeta Recent de Microsoft Office
- Jumplists

Herramientas como [**USBDetective**](https://usbdetective.com) correlacionan estos artefactos con los registros de dispositivos USB, pero la disponibilidad de los artefactos depende de la versión de Windows y de la aplicación.<sup>[[18]](#references)</sup>

En las pruebas documentadas para flujos de trabajo MTP de Windows XP y Windows 7, algunos LNK apuntaban a una carpeta `WPDNSE` en lugar de la ruta original.<sup>[[16]](#references)</sup>

![Shellbags - Uso de dispositivos USB en Windows: Ten en cuenta que algunos archivos LNK, en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE](<../../../images/image (218).png>)

Ese estudio observó copias en `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; el contenido temporal no sobrevivió a un reinicio en sus pruebas, y el GUID podía correlacionarse con los datos de shellbag. Trata esto como un comportamiento dependiente del sistema operativo, el dispositivo y la aplicación, no como una regla universal.<sup>[[16]](#references)</sup>

### Información del Registro

[Consulta esta página para saber](interesting-windows-registry-keys.md#usb-information) qué claves del Registro contienen información interesante sobre los dispositivos USB conectados.

### setupapi

En Vista y versiones posteriores, inspecciona `C:\Windows\inf\setupapi.dev.log` para buscar actividad de instalación de dispositivos. Las cabeceras de sección incluyen marcas de tiempo `Section start`; documentan el procesamiento de la instalación y deben correlacionarse con otras evidencias de conexión, en lugar de tratarse como la hora exacta de inserción física.<sup>[[17]](#references)</sup>

![Información del Registro - setupapi: Consulta el archivo C: Windows inf setupapi.dev.log para obtener las marcas de tiempo sobre cuándo se produjo la conexión USB (busca Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) puede utilizarse para obtener información sobre los dispositivos USB que se han conectado a una imagen.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective puede utilizarse para obtener información sobre los dispositivos USB que se han conectado a una imagen](<../../../images/image (452).png>)

### Plug and Play Cleanup

La tarea programada conocida como `Plug and Play Cleanup` elimina versiones obsoletas de controladores. Una definición de tarea de Windows 10 documentada por Adam Harrison también apunta a controladores inactivos durante 30 días, por lo que la evidencia de controladores de dispositivos extraíbles puede limpiarse; confirma la definición de tarea local y la compilación de Windows antes de generalizar este comportamiento.<sup>[[1]](#references)</sup>

La tarea se encuentra en la siguiente ruta: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Definición XML de la tarea programada Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes y configuraciones principales de la tarea:**

- **pnpclean.dll**: Esta DLL es responsable del proceso de limpieza real.
- **UseUnifiedSchedulingEngine**: Establecido en `TRUE`, indica el uso del motor genérico de programación de tareas.
- **MaintenanceSettings**:
- **Period ('P1M')**: Indica al Programador de tareas que inicie la tarea de limpieza mensualmente durante el mantenimiento Automatic normal.
- **Deadline ('P2M')**: Indica al Programador de tareas que, si la tarea falla durante dos meses consecutivos, ejecute la tarea durante el mantenimiento Automatic de emergencia.

Esta configuración programa el mantenimiento regular y los reintentos después de fallos consecutivos; el XML exacto y el comportamiento dependen de la versión.<sup>[[1]](#references)</sup>

**Para obtener más información, consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emails

Los Emails contienen **2 partes interesantes: las cabeceras y el contenido** del Email. En las **cabeceras** puedes encontrar información como:

- **Quién** envió los Emails (dirección de Email, IP, servidores de correo que han redirigido el Email)
- **Cuándo** se envió el Email

Además, las cabeceras `References` e `In-Reply-To` pueden contener IDs de mensaje utilizados para asociar las respuestas con una conversación.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Cuándo se envió el Email](<../../../images/image (593).png>)

### Aplicación Windows Mail

Esta aplicación guarda el contenido de los Emails en archivos de texto o HTML auxiliares en rutas como `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; la carpeta numerada exacta y la estructura de archivos pueden variar según el artefacto.<sup>[[75]](#references)</sup>

Los **metadatos** de los Emails y los **contactos** se encuentran dentro de la **base de datos ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` utiliza el formato Extensible Storage Engine (ESE). Trabaja sobre una copia y utiliza un parser ESE como [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); si una herramienta requiere el sufijo `.edb`, cambia el nombre únicamente de la copia y verifica el esquema de las tablas antes de confiar en una tabla `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Al inspeccionar las propiedades MAPI de Outlook, las propiedades canónicas incluyen:

- `PidTagClientSubmitTime`: la hora UTC en la que el cliente envió el mensaje.
- `PidTagConversationIndex`: la posición relativa del mensaje en un hilo de conversación.
- `PidTagEntryId`: un identificador del objeto de mensaje.
- `PidTagMessageFlags`: indicadores de estado como enviado, leído, no leído o con archivos adjuntos.
- `PidTagLastVerbExecuted`: la última operación registrada para el mensaje, como abrir, responder o reenviar.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Las ubicaciones de los archivos de datos de Outlook varían según la versión y el tipo de cuenta. Microsoft documenta estas ubicaciones habituales para los archivos PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

La ruta del Registro `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` puede identificar el perfil de Outlook y la configuración de los archivos de datos asociados.

Los archivos PST pueden contener mensajes, contactos, datos del calendario y otros elementos de Outlook. Puedes inspeccionar una copia con [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Aplicación Windows Mail - Microsoft Outlook: Puedes abrir el archivo PST utilizando la herramienta Kernel PST Viewer](<../../../images/image (498).png>)

### Archivos OST de Microsoft Outlook

Un **archivo OST** es una caché local para cuentas de Exchange o Microsoft 365; el modo Cached Exchange no se aplica a cuentas POP o IMAP. El período sin conexión es configurable y suele ser de 12 meses de forma predeterminada, mientras que los límites de tamaño de PST/OST son configuraciones independientes y configurables. Para ver un archivo OST, se puede utilizar [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Recuperación de archivos adjuntos

Los archivos adjuntos perdidos podrían recuperarse de:

- Para configuraciones heredadas de Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Para configuraciones más recientes de Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Archivos MBOX de Thunderbird

**Thunderbird** almacena los datos del perfil en `%APPDATA%\Thunderbird\Profiles`; las carpetas de correo suelen utilizar archivos mbox sin extensión en los directorios `Mail` o `ImapMail` específicos de cada cuenta.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniaturas de imágenes

- **Windows XP**: Las vistas previas de miniaturas se almacenaban habitualmente en archivos `thumbs.db` por carpeta.
- **Carpetas de red**: Todavía puede crearse un archivo `thumbs.db` para una carpeta UNC cuando está habilitado el comportamiento de miniaturas correspondiente; no asumas que todas las versiones o políticas de Windows crean uno.
- **Windows Vista y posteriores**: La caché de miniaturas del sistema está centralizada en `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, con archivos como **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) puede analizar `Thumbs.db` heredados, mientras que [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) puede analizar bases de datos modernas de caché de miniaturas.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Información del Registro de Windows

El Registro de Windows, que almacena datos de configuración del sistema y del usuario, está contenido en archivos hive ubicados en:

- `%WINDIR%\System32\Config` para los hives de la máquina que respaldan varias subclaves de `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` para el hive `HKEY_CURRENT_USER` de un usuario.
- Algunas instalaciones antiguas de Windows contienen copias en `%WINDIR%\System32\Config\RegBack\`; Windows 10 versión 1803 y posteriores no rellenan automáticamente este directorio a menos que esté habilitada la copia de seguridad periódica.<sup>[[34]](#references)[[35]](#references)</sup>
- Los datos de shell y registro de clases por usuario también se almacenan habitualmente en `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` en versiones modernas de Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Algunas herramientas son útiles para analizar hives del Registro; confirma los formatos de hive y las versiones compatibles con cada herramienta antes de confiar en un resultado:

- **Registry Editor**: Está instalado en Windows. Es una GUI para navegar por el Registro de Windows de la sesión actual.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite cargar el archivo del Registro y navegar por él mediante una GUI. También contiene Bookmarks que resaltan claves con información interesante.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): De nuevo, cuenta con una GUI que permite navegar por el Registro cargado y también contiene plugins que resaltan información interesante dentro del Registro cargado.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Otra aplicación GUI capaz de extraer información de un hive del Registro cargado.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recuperación de elementos eliminados

Las celdas de hive eliminadas pueden permanecer hasta que se reutilice su espacio, pero la recuperación depende del estado del hive y del parser; trata las claves eliminadas recuperadas como evidencia que requiere validación, no como registros garantizados.

### Hora de última escritura

Las claves del Registro contienen una marca de tiempo de última escritura; Windows la expone para la clave o cualquiera de sus entradas de valor, por lo que un valor no necesariamente tiene su propia marca de tiempo de modificación independiente.<sup>[[69]](#references)</sup>

### SAM

El hive **SAM** contiene datos de cuentas de usuarios y grupos locales, incluidos hashes de contraseñas protegidos por el material de boot-key del sistema.<sup>[[38]](#references)[[39]](#references)</sup>

En `SAM\Domains\Account\Users` puedes obtener identificadores de cuentas y algunos campos de inicio de sesión y políticas. La extracción offline de hashes también requiere el hive `SYSTEM` para recuperar el material de boot-key relevante.<sup>[[38]](#references)[[39]](#references)</sup>

### Entradas interesantes en el Registro de Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programas ejecutados

### Procesos básicos de Windows

Se conserva un [post sobre procesos comunes de Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) como lectura adicional; corrobora cualquier afirmación sobre el comportamiento de los procesos con la documentación actual de Windows y la evidencia local.<sup>[[2]](#references)</sup>

### Aplicaciones recientes de Windows

En las versiones de Windows 10 que lo exponen, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` contiene subclaves por aplicación con campos como la hora del último uso y el número de ejecuciones; el artefacto se eliminó en versiones posteriores, por lo que debes validar la compilación objetivo.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

En los sistemas que exponen Background Activity Moderator, inspecciona la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` o la ruta más reciente `...\bam\State\UserSettings\{SID}`. Los valores están asociados al SID del usuario y pueden contener rutas de ejecutables rastreados y datos de ejecución similares a FILETIME; el artefacto depende de la versión y debe corroborarse con otras evidencias.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch almacena en caché recursos y metadatos de ejecución para que los programas puedan iniciarse más rápidamente.

Los archivos Prefetch se almacenan como archivos `.pf` en `C:\Windows\Prefetch`; el formato, la retención y los límites de cantidad de archivos varían según la versión de Windows. Microsoft documenta la retención de las últimas ocho horas de ejecución y de hasta 1024 archivos en Windows 8 y posteriores, por lo que los resúmenes antiguos basados en límites fijos no deben generalizarse.<sup>[[13]](#references)</sup>

El nombre de archivo suele utilizar el formato `{program_name}-{hash}.pf`, donde el hash se deriva del contexto de ejecución, como la ruta y los argumentos; Windows 10 y posteriores pueden comprimir el archivo. Su presencia es una evidencia útil de ejecución, pero por sí sola no demuestra que el usuario lo haya ejecutado y debe correlacionarse con otros artefactos.<sup>[[13]](#references)</sup>

Para inspeccionar estos archivos puedes utilizar [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), que documenta el análisis de directorios, la salida CSV/HTML y la compatibilidad con la descompresión de los archivos Prefetch aplicables de Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** complementa Prefetch mediante el uso de patrones históricos de uso para mejorar la carga. En los sistemas que los generan, sus archivos de base de datos suelen encontrarse en `C:\Windows\Prefetch\Ag*.db`; el formato y la presencia dependen de la versión.<sup>[[41]](#references)</sup>

Estas bases de datos pueden contener nombres de aplicaciones, recuentos de uso, archivos o volúmenes accedidos, rutas y rangos temporales, pero no deben tratarse como un registro exacto de ejecución.<sup>[[41]](#references)</sup>

Se conserva el enlace existente a [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) como posible parser; verifica su disponibilidad actual y el formato de salida compatible con la documentación de la herramienta antes de usarlo.

### SRUM

**System Resource Usage Monitor** (SRUM) registra el uso de recursos por parte de aplicaciones y usuarios. Se introdujo en Windows 8 y almacena los datos en la base de datos ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Proporciona la siguiente información:

- AppID y ruta
- Usuario/SID asociado al registro
- Bytes enviados
- Bytes recibidos
- Interfaz de red
- Duración de la conexión
- Duración del proceso

La frecuencia de recopilación y la retención dependen de la implementación; no asumas que cada registro representa un intervalo exacto de ejecución de 60 minutos.<sup>[[13]](#references)</sup>

Puedes extraer y revisar los datos con [**srum_dump**](https://github.com/MarkBaggett/srum-dump), usando las opciones documentadas por la versión actual de la herramienta.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

La **AppCompatCache**, también conocida como **ShimCache**, forma parte de la infraestructura de compatibilidad de aplicaciones de Windows y registra metadatos de archivos para las decisiones de compatibilidad. La ruta de la hive, el formato de los registros, la capacidad de retención y los campos varían según la versión de Windows; en las versiones modernas de Windows, la ShimCache por sí sola no puede demostrar que un usuario ejecutó un archivo. Analiza la hive `SYSTEM` correspondiente con la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) y corrobora su salida con artefactos de ejecución.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Para analizar la información almacenada, se recomienda utilizar la herramienta AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

El archivo **Amcache.hve** es una hive del registro que realiza un inventario de las aplicaciones y los archivos observados por Windows. Normalmente se encuentra en `C:\Windows\AppCompat\Programs\Amcache.hve`.

Puede contener entradas de archivos asociados y no asociados, rutas y valores SHA1, pero su presencia constituye evidencia de inventario y no demuestra por sí misma que un proceso se haya ejecutado.<sup>[[13]](#references)[[44]](#references)</sup>

Para extraer y analizar **Amcache.hve**, utiliza la herramienta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Este comando analiza la hive y escribe la salida en formato CSV.<sup>[[44]](#references)</sup>

Por ejemplo:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre los archivos CSV generados, `Amcache_Unassociated file entries` puede ser útil al investigar archivos que no están asociados con un programa reconocido.<sup>[[44]](#references)</sup>

### RecentFileCache

En sistemas Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` puede contener información sobre binarios observados recientemente; su disponibilidad y semántica dependen de la versión.

Puedes usar [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) para analizar el archivo.<sup>[[45]](#references)</sup>

### Tareas programadas

La evidencia de las tareas programadas puede encontrarse en `C:\Windows\System32\Tasks` para las tareas modernas y en `C:\Windows\Tasks` con archivos `.job` para las tareas heredadas; inspecciona el formato de definición de tareas apropiado para el sistema operativo.<sup>[[73]](#references)[[74]](#references)</sup>

### Servicios

La base de datos del Service Control Manager se encuentra en `SYSTEM\CurrentControlSet\Services` (para un hive SYSTEM sin conexión, inspecciona la clave del control-set correspondiente); contiene la configuración de servicios y drivers, como las rutas de los ejecutables y los tipos de inicio.<sup>[[72]](#references)</sup>

### **Windows Store**

Las aplicaciones de Windows Store instaladas pueden estar representadas en `\ProgramData\Microsoft\Windows\AppRepository\`, incluida la base de datos **`StateRepository-Machine.srd`**. El esquema y las rutas varían según la versión de Windows.<sup>[[71]](#references)</sup>

La base de datos puede contener identificadores de aplicaciones, números de paquetes y nombres para mostrar. Las brechas en los identificadores no constituyen, por sí solas, una prueba de que una aplicación haya sido desinstalada; corrobóralo con el estado de los paquetes y del registro.

Los registros de paquetes también pueden aparecer en `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft documenta una subclave `Deprovisioned` específica de cada versión para las aplicaciones provisionadas eliminadas; no asumas que existe una subclave `Deleted` en todas las compilaciones.<sup>[[70]](#references)</sup>

## Windows Events

Según el proveedor, los eventos de Windows pueden contener:

- Qué ocurrió
- Una marca de tiempo `TimeCreated` que debe interpretarse junto con el esquema del evento y el contexto horario del host
- Usuarios implicados
- Hosts implicados (nombre de host, IP)
- Activos a los que se accedió (archivos, carpetas, impresoras o servicios).<sup>[[49]](#references)</sup>

Antes de Windows Vista, los registros de eventos generalmente usaban el formato binario heredado en `C:\Windows\System32\config`; Vista y las versiones posteriores usan el formato Windows Event Log, normalmente en `C:\Windows\System32\winevt\Logs`, con archivos `.evtx` que contienen datos de eventos representados en XML.<sup>[[46]](#references)[[47]](#references)</sup>

El registro SYSTEM almacena la configuración de los canales en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, incluida la ruta de archivo configurada y los ajustes de retención.<sup>[[47]](#references)</sup>

Pueden visualizarse con Windows Event Viewer (**`eventvwr.msc`**) o con herramientas como [**Event Log Explorer**](https://eventlogxp.com) y [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

En Vista y versiones posteriores, el canal Security suele almacenarse en `C:\Windows\System32\winevt\Logs\Security.evtx`. Su tamaño máximo y la política de retención son configurables; con el registro circular, los registros antiguos pueden sobrescribirse cuando el archivo alcanza su límite. El canal puede registrar eventos de autenticación, cierre de sesión, privilegios, políticas de auditoría y acceso a objetos cuando la auditoría correspondiente está habilitada.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Un inicio de sesión de cuenta exitoso.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Un inicio de sesión de cuenta fallido.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Se terminó una sesión de inicio de sesión.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Un usuario inició un cierre de sesión.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Se asignaron privilegios especiales a un nuevo inicio de sesión; esto es habitual en cuentas del sistema y de administrador, por lo que no constituye por sí solo una prueba de actividad maliciosa.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: Un inicio de sesión local interactivo.
- **Network (3)**: Acceso a un recurso compartido.
- **Batch (4)**: Un inicio de sesión de proceso por lotes.
- **Service (5)**: Un inicio de sesión de servicio.
- **Unlock (7)**: Desbloqueo de una estación de trabajo.
- **NetworkCleartext (8)**: Un inicio de sesión de red que proporciona credenciales en texto claro al paquete de autenticación.
- **NewCredentials (9)**: Un inicio de sesión que utiliza credenciales alternativas proporcionadas para conexiones salientes.
- **RemoteInteractive (10)**: Un inicio de sesión mediante Remote Desktop o Terminal Services.
- **CachedInteractive (11)**: Un inicio de sesión interactivo que utiliza credenciales de dominio almacenadas en caché.
- **CachedRemoteInteractive (12)**: Un inicio de sesión remoto interactivo almacenado en caché.
- **CachedUnlock (13)**: Un desbloqueo mediante credenciales almacenadas en caché.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: No existe tal usuario.
- **0xC000006A**: Nombre de usuario correcto, pero contraseña incorrecta.
- **0xC0000234**: Cuenta bloqueada.
- **0xC0000072**: Cuenta deshabilitada.
- **0xC000006F**: Inicio de sesión fuera del horario permitido.
- **0xC0000070**: Incumplimiento de la restricción de estación de trabajo.
- **0xC0000193**: Cuenta expirada.
- **0xC0000071**: Contraseña expirada.
- **0xC0000133**: La diferencia de hora entre el cliente y el servidor es demasiado grande.
- **0xC0000224**: La cuenta debe cambiar su contraseña.
- **0xC0000225**: `STATUS_NOT_FOUND`; el código por sí solo no identifica un error del sistema ni un ataque.
- **0xC000015B**: El tipo de inicio de sesión solicitado no está concedido a la cuenta.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Se cambió la hora del sistema. Muchos eventos reflejan una corrección rutinaria del servicio de hora, por lo que debes correlacionar el actor y la fuente de tiempo antes de considerarlo una manipulación.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: El evento 12 registra el inicio del sistema operativo, el 13 registra el apagado del sistema operativo, el 1074 registra un apagado o reinicio planificado, el 6008 indica un apagado inesperado y el 6009 registra la versión de Windows durante el arranque. Los eventos 6005 y 6006 indican, respectivamente, que el servicio Event Log se inició y se detuvo; por sí mismos, no prueban el inicio ni el apagado del sistema operativo.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: El evento 1102 registra que se borró el registro de auditoría de Security; investiga el actor y los eventos circundantes en lugar de asumir una intención basándote únicamente en este evento.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: Eventos de instalación de dispositivos de `UserPnp` que pueden ayudar a establecer la primera utilización o actividad de instalación.
- **10000 / 10100**: Eventos de `DriverFrameworks-UserMode` que pueden acompañar a la actividad del dispositivo.
- **Event ID 112**: Actividad de `DeviceSetupManager/Admin` que puede proporcionar marcas de tiempo relacionadas con la inserción.
- El proveedor, el canal y la semántica de los eventos varían según la versión de Windows; inspecciona el nombre del proveedor y la carga útil del evento antes de asignarle un significado.<sup>[[59]](#references)</sup>

Para consultar ejemplos prácticos sobre los tipos de inicio de sesión y su material de credenciales asociado, consulta la [guía detallada de Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Los detalles del evento, incluidos el tipo de inicio de sesión, el estado, el subestado, la dirección de origen y los campos del proceso, proporcionan contexto para el Event ID 4625; un código de estado o un patrón de fallos repetidos constituye una pista de investigación, no una conclusión.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Dado que los registros de eventos suelen ser circulares, los registros sobrescritos por el logger pueden ser irrecuperables. Conserva una imagen forense o una copia de trabajo antes de interactuar con un sistema activo; utiliza un parser o carver validado, como **Bulk_extractor**, solo después de confirmar que la versión de la herramienta admite los datos `.evtx` objetivo, y no desconectes un sistema en ejecución únicamente para intentar recuperar eventos.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Para consultar una referencia práctica de event-ID, consulta el enlace existente de [Red Team Recipe](https://redteamrecipe.com/event-codes/) y valida sus ejemplos con la documentación del proveedor anterior.

#### Brute Force Attacks

Correlaciona los fallos repetidos del Event ID 4625 con un éxito posterior del 4624, el tipo de inicio de sesión, el estado, el origen y el contexto de la cuenta; la secuencia es un indicador para investigar, no una prueba de un ataque.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

El Event ID 4616 registra los cambios de hora del sistema, lo que puede complicar el análisis de la línea temporal; compáralo con la evidencia del servicio de hora y del host.<sup>[[56]](#references)</sup>

#### USB Device Tracking

Los event IDs de USB son específicos del proveedor; correlaciona `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 y `DeviceSetupManager/Admin` 112 con los artefactos de SetupAPI y del registro.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Utiliza 12/13/1074/6008/6009 para el contexto de inicio, apagado, reinicio y pérdida inesperada de alimentación del sistema operativo; 6005/6006 marcan el inicio y la detención del servicio Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

El Security Event ID 1102 registra que se borró el registro de auditoría de Security y debe correlacionarse con la cuenta y el proceso responsables.<sup>[[62]](#references)</sup>

## References

- [1] [Limpieza de Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigación de procesos comunes de Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Una perspectiva de Digital Forensics sobre las notificaciones de Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Herramientas forenses de Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier y Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operaciones de copia de seguridad y restauración del registro mediante VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Claves del registro para copia de seguridad y restauración](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problema de rendimiento de Word en la ubicación de AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Manual de respuesta a incidentes](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: formato binario de archivo Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Digital Forensics de USB MTP: identificación de artefactos de exfiltración de datos](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Entradas del registro de instalación de dispositivos de SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID y tipos relacionados](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Buscar y transferir archivos de datos de Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Activar Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Solo se sincroniza un subconjunto de elementos](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configurar límites de tamaño para archivos de datos de Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Perfiles: dónde almacena Thunderbird los datos del usuario](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Configuración de cuentas de Thunderbird y directorios mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interfaz IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Hives del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [El registro del sistema no se respalda en RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Editar remotamente el registro](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Descripción técnica de las contraseñas](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Evidencia de Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Formato de archivo Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Clave del registro de Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Propiedad de evento TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Evento 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Evento 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Evento 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Evento 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Evento 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: valores NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Evento 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Solucionar reinicios inesperados mediante los registros de eventos del sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Solucionar el apagado en curso](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Digital Forensics de dispositivos de almacenamiento USB para Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Tipos de inicio de sesión fantásticos de Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Evento 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderador de actividad en segundo plano](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registro - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print deja de imprimir archivos adjuntos PDF en Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Archivos del registro de Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Evitar que las aplicaciones eliminadas regresen durante una actualización](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: resultados de pruebas de FTK y Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Base de datos de servicios instalados](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tareas](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks falla con el error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navegación por la base de datos de Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: formato de mensajes de Internet](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
