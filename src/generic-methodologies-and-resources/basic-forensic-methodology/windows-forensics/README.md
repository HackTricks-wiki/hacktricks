# Artefactos de Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos genéricos de Windows

### Notificaciones de Windows 10

La base de datos de notificaciones por usuario se encuentra en `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (por ejemplo, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Las primeras versiones de Windows 10 usaban `appdb.dat`; la Anniversary Update (1607) introdujo `wpndatabase.db`. La base de datos SQLite incluye una tabla `Notification` con cargas útiles de notificaciones y campos de fecha y hora, aunque la retención y los datos disponibles varían según la versión y la política de limpieza.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline es una función de historial de actividad que puede contener registros de aplicaciones compatibles, documentos y otras actividades del usuario; su cobertura depende de la aplicación y de la versión de Windows.<sup>[[4]](#references)</sup>

La base de datos se encuentra en `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Puede abrirse con SQLite o analizarse con [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd); su salida puede revisarse con [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### Instantáneas de Windows Recall (PC Copilot+)

Recall es una función opcional en los PC Copilot+ compatibles con Windows 11. Las versiones actuales cifran las instantáneas y su índice con claves vinculadas a Windows Hello y a un enclave VBS. No consideres una copia sin conexión del almacén como una base de datos SQLite en texto plano; la versión preliminar de 2024 y el diseño publicado tienen propiedades de acceso distintas.<sup>[[77]](#references)</sup>

En una **sesión activa de Recall habilitada**, el proceso de representación `AIXHost.exe` del mismo usuario ofrece una superficie de acceso diferente. La prueba de concepto TotalRecall Reloaded inyecta una DLL en ese proceso y llama a sus interfaces COM de Recall. Para extraer todo el historial, el usuario aún debe autenticarse con Windows Hello; esto no es un descifrado sin conexión ni una omisión de Hello. El investigador documentó la herramienta en Windows 11 ARM64, así que verifica la compatibilidad con la versión de destino antes de confiar en ella.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` usa `GetRecentCaptureThumbnail` para solicitar una versión de alta resolución de la captura más reciente sin Hello. Tras la autorización, `--wait` puede extraer capturas de pantalla, texto OCR y metadatos por captura, incluidos el contexto de la aplicación y de la ventana. La salida se escribe en un directorio `extraction_*` con marca de tiempo. Estos hallazgos dependen de la build y proceden de la prueba de concepto; no garantizan que Recall esté habilitado ni que se haya capturado cada pantalla.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

Los archivos descargados desde fuera del límite de confianza local pueden contener el **flujo de datos alternativo `Zone.Identifier`**, que registra información de zona y puede incluir metadatos de origen, como una URL. Su presencia y sus campos dependen del productor y de la política del sistema.<sup>[[6]](#references)</sup>

## **Copias de seguridad de archivos**

### Papelera de reciclaje

En Vista y versiones posteriores, la **Papelera de reciclaje** se encuentra en la carpeta **`$Recycle.bin`** en la raíz de la unidad (por ejemplo, `C:\$Recycle.bin`).\
Cuando se elimina un archivo en esta carpeta, se crean 2 archivos específicos:

- `$I{id}`: Información del archivo, incluida la hora de eliminación y la ruta original
- `$R{id}`: Contenido del archivo

![Copias de seguridad de archivos - Papelera de reciclaje: $R{id}: Contenido del archivo](<../../../images/image (1029).png>)

Con estos archivos, puedes usar [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) para extraer la ruta original y la hora de eliminación (usa la versión adecuada para la versión de Windows de destino).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Copias de seguridad de archivos - Papelera de reciclaje: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Copias sombra de volumen

Volume Shadow Copy Service (VSS) puede crear copias sombra de volúmenes en un momento determinado mientras los archivos están en uso; una copia sombra no sustituye a una imagen forense.<sup>[[8]](#references)</sup>

Los metadatos de las copias suelen estar asociados a `\System Volume Information` en la raíz del volumen, con identificadores que varían según el sistema:

![Papelera de reciclaje - Copias sombra de volumen: Estas copias de seguridad suelen estar en System Volume Information, en la raíz del sistema de archivos, y el nombre se compone de UID que se muestran en...](<../../../images/image (94).png>)

Tras montar una imagen con un montador forense adecuado, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) puede enumerar las instantáneas VSS disponibles y explorar o copiar archivos de ellas.<sup>[[9]](#references)</sup>

![Papelera de reciclaje - Copias sombra de volumen: Al montar la imagen forense con ArsenalImageMounter, se puede usar la herramienta ShadowCopyView para inspeccionar una copia sombra e incluso extraer los archivos...](<../../../images/image (576).png>)

La configuración del escritor de registro de VSS incluye `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, que puede especificar archivos y claves excluidos de la copia de seguridad:<sup>[[10]](#references)[[11]](#references)</sup>

![Papelera de reciclaje - Copias sombra de volumen: La entrada del registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contiene los archivos y claves que no se deben respaldar](<../../../images/image (254).png>)

La clave `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` también contiene la configuración del servicio VSS.<sup>[[8]](#references)</sup>

### Archivos guardados automáticamente de Office

Las ubicaciones de AutoRecover varían según la aplicación de Office, la versión y la configuración. Para Word, Microsoft documenta `%APPDATA%\Microsoft\Word` como la ubicación predeterminada; comprueba la configuración de la aplicación para conocer la ruta activa.<sup>[[12]](#references)</sup>

## Elementos de Shell

Un elemento de Shell es un elemento que contiene información sobre cómo acceder a otro archivo.

### Documentos recientes (LNK)

Windows suele crear accesos directos a elementos recientes cuando un usuario abre un elemento o accede a él de otro modo:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

El acceso a una carpeta también puede crear vínculos para la carpeta y las carpetas principales relacionadas.

Estos archivos de vínculo pueden contener el tipo de destino, las marcas de tiempo MAC del destino, información del volumen y la ruta del destino. Estos metadatos pueden ayudar a identificar un destino eliminado, pero el artefacto no demuestra por sí solo que un usuario concreto haya abierto el destino.<sup>[[13]](#references)[[14]](#references)</sup>

Las marcas de tiempo del sistema de archivos del propio LNK y las marcas de tiempo del destino incrustadas son distintas. No interpretes la creación del vínculo como el primer uso ni la modificación del vínculo como el último uso sin artefactos que lo corroboren; el formato almacena las marcas de tiempo del destino por separado de las del archivo de vínculo.<sup>[[13]](#references)[[14]](#references)</sup>

Se conserva el vínculo existente a [**LinkParser**](http://4discovery.com/our-tools/) como opción histórica, pero su documentación no estaba disponible durante la revisión. Para un analizador documentado de línea de comandos, usa [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Estas herramientas suelen mostrar dos conjuntos de marcas de tiempo:

- **Marcas de tiempo del destino:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Marcas de tiempo del archivo de vínculo:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

El primer conjunto corresponde al destino; el segundo, al propio archivo LNK. Interpreta ambos según la documentación del analizador y el contexto del sistema de archivos.<sup>[[14]](#references)[[15]](#references)</sup>

Puedes obtener la misma información ejecutando la herramienta CLI de Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

En este caso, la información se guardará en un archivo CSV.

### Jumplists

Las Jump Lists son listas por aplicación de elementos recientes o específicos de tareas, y pueden ser automáticas o personalizadas.<sup>[[13]](#references)</sup>

Las Jump Lists automáticas se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` y usan nombres como `{id}.automaticDestinations-ms`, donde el ID identifica la aplicación.

Las Jump Lists personalizadas se almacenan en `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; la aplicación controla qué entradas de tareas o elementos crea.

Las horas de creación y modificación del sistema de archivos describen el archivo Jump List, no necesariamente el primer y el último acceso a cada destino de la lista. Correlaciona las entradas analizadas con las marcas de tiempo del archivo y otros artefactos.<sup>[[13]](#references)</sup>

Puedes inspeccionar las Jump Lists con [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Documentos recientes (LNK) - Jumplists: Puedes inspeccionar las jumplists con JumplistExplorer](<../../../images/image (168).png>)

(_Ten en cuenta que las marcas de tiempo proporcionadas por JumplistExplorer corresponden al archivo jumplist_)

### Shellbags

[**Sigue este enlace para aprender qué son las shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de dispositivos USB en Windows

En ocasiones, el uso de dispositivos USB puede corroborarse mediante artefactos creados cuando se accede a archivos desde medios extraíbles, entre ellos:

- Carpeta Windows Recent
- Carpeta Microsoft Office Recent
- Jumplists

Herramientas como [**USBDetective**](https://usbdetective.com) correlacionan estos artefactos con registros de dispositivos USB, pero la disponibilidad de los artefactos depende de la versión de Windows y de la aplicación.<sup>[[18]](#references)</sup>

En pruebas documentadas para flujos de trabajo MTP en Windows XP y Windows 7, algunos LNK apuntaban a una carpeta `WPDNSE` en lugar de a la ruta original.<sup>[[16]](#references)</sup>

![Shellbags - Uso de dispositivos USB en Windows: Ten en cuenta que algunos archivos LNK, en lugar de apuntar a la ruta original, apuntan a la carpeta WPDNSE](<../../../images/image (218).png>)

Ese estudio observó copias en `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; en sus pruebas, el contenido temporal no sobrevivió a un reinicio, y el GUID podía correlacionarse con datos de shellbag. Considera que este comportamiento depende del sistema operativo, el dispositivo y la aplicación, y no es una regla universal.<sup>[[16]](#references)</sup>

### Información del registro

[Consulta esta página para saber](interesting-windows-registry-keys.md#usb-information) qué claves del registro contienen información de interés sobre dispositivos USB conectados.

### setupapi

En Vista y versiones posteriores, inspecciona `C:\Windows\inf\setupapi.dev.log` para encontrar actividad de instalación de dispositivos. Los encabezados de sección incluyen marcas de tiempo `Section start`; documentan el procesamiento de la instalación y deben correlacionarse con otras pruebas de conexión, en lugar de tratarse como la hora exacta de la conexión física.<sup>[[17]](#references)</sup>

![Información del registro - setupapi: Consulta el archivo C: Windows inf setupapi.dev.log para obtener las marcas de tiempo de cuándo se produjo la conexión USB (busca Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) puede utilizarse para obtener información sobre los dispositivos USB que se han conectado a una imagen.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective puede utilizarse para obtener información sobre los dispositivos USB que se han conectado a una imagen](<../../../images/image (452).png>)

### Limpieza de Plug and Play

La tarea programada conocida como `Plug and Play Cleanup` elimina versiones obsoletas de controladores. Una definición de tarea de Windows 10 documentada por Adam Harrison también apunta a controladores inactivos durante 30 días, por lo que es posible que se eliminen pruebas de controladores de dispositivos extraíbles; confirma la definición de tarea local y la compilación de Windows antes de generalizar este comportamiento.<sup>[[1]](#references)</sup>

La tarea se encuentra en la siguiente ruta: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Definición XML de la tarea programada Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes y ajustes principales de la tarea:**

- **pnpclean.dll**: Esta DLL es responsable del proceso de limpieza.
- **UseUnifiedSchedulingEngine**: Establecido en `TRUE`, indica el uso del motor genérico de programación de tareas.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Indica al Task Scheduler que inicie la tarea de limpieza mensualmente durante el mantenimiento automático habitual.
  - **Deadline ('P2M')**: Indica al Task Scheduler que, si la tarea falla durante dos meses consecutivos, la ejecute durante el mantenimiento automático de emergencia.

Esta configuración programa el mantenimiento periódico y los reintentos tras fallos consecutivos; el XML exacto y el comportamiento dependen de la versión.<sup>[[1]](#references)</sup>

**Para más información, consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Correos electrónicos

Los correos electrónicos contienen **2 partes de interés: los encabezados y el contenido** del correo. En los **encabezados** puedes encontrar información como:

- **Quién** envió los correos (dirección de correo electrónico, IP y servidores de correo que los redirigieron)
- **Cuándo** se envió el correo

Además, los encabezados `References` y `In-Reply-To` pueden contener identificadores de mensaje que sirven para asociar las respuestas con una conversación.<sup>[[76]](#references)</sup>

![Limpieza de Plug and Play - Correos electrónicos: Cuándo se envió el correo](<../../../images/image (593).png>)

### Aplicación Windows Mail

Esta aplicación guarda el contenido de los correos en archivos auxiliares de texto o HTML en rutas como `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; la carpeta numerada exacta y la estructura de los archivos pueden variar según el artefacto.<sup>[[75]](#references)</sup>

Los **metadatos** de los correos y los **contactos** se encuentran en la **base de datos ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` usa el formato Extensible Storage Engine (ESE). Trabaja sobre una copia y usa un analizador ESE como [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); si una herramienta requiere la extensión `.edb`, cambia el nombre solo a la copia y verifica el esquema de las tablas antes de confiar en una tabla `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Al inspeccionar las propiedades MAPI de Outlook, entre las propiedades canónicas se encuentran:

- `PidTagClientSubmitTime`: hora UTC a la que el cliente envió el mensaje.
- `PidTagConversationIndex`: posición relativa del mensaje en un hilo de conversación.
- `PidTagEntryId`: identificador del objeto de mensaje.
- `PidTagMessageFlags`: indicadores de estado, como enviado, leído, no leído o con archivos adjuntos.
- `PidTagLastVerbExecuted`: última operación registrada para el mensaje, como abrir, responder o reenviar.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Las ubicaciones de los archivos de datos de Outlook varían según la versión y el tipo de cuenta. Microsoft documenta estas ubicaciones comunes para archivos PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

La ruta del registro `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` puede identificar el perfil de Outlook y la configuración asociada de los archivos de datos.

Los archivos PST pueden contener mensajes, contactos, datos de calendario y otros elementos de Outlook. Puedes inspeccionar una copia con [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Aplicación Windows Mail - Microsoft Outlook: Puedes abrir el archivo PST con la herramienta Kernel PST Viewer](<../../../images/image (498).png>)

### Archivos OST de Microsoft Outlook

Un **archivo OST** es una caché local para cuentas de Exchange o Microsoft 365; el modo Cached Exchange no se aplica a cuentas POP o IMAP. El período sin conexión es configurable y suele ser de 12 meses de forma predeterminada, mientras que los límites de tamaño de PST/OST son ajustes configurables independientes. Para ver un archivo OST, se puede utilizar [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Recuperación de archivos adjuntos

Es posible que los archivos adjuntos perdidos se puedan recuperar de:

- Para configuraciones heredadas de Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Para configuraciones más recientes de Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Archivos MBOX de Thunderbird

**Thunderbird** almacena los datos del perfil en `%APPDATA%\Thunderbird\Profiles`; las carpetas de correo suelen usar archivos mbox sin extensión en directorios `Mail` o `ImapMail` específicos de la cuenta.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniaturas de imágenes

- **Windows XP**: Las vistas previas en miniatura solían guardarse en archivos `thumbs.db` de cada carpeta.
- **Carpetas de red**: Es posible que se cree un archivo `thumbs.db` para una carpeta UNC si está habilitado el comportamiento de miniaturas correspondiente; no des por sentado que todas las versiones o directivas de Windows crean uno.
- **Windows Vista y versiones posteriores**: La caché de miniaturas del sistema está centralizada en `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, en archivos como **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) puede analizar archivos `Thumbs.db` heredados, mientras que [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) puede analizar bases de datos modernas de caché de miniaturas.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Información del registro de Windows

El Registro de Windows, que almacena datos de configuración del sistema y de los usuarios, se encuentra en archivos hive en:

- `%WINDIR%\System32\Config` para los hives de máquina que respaldan varias subclaves de `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` para el hive `HKEY_CURRENT_USER` de un usuario.
- Algunas instalaciones antiguas de Windows contienen copias en `%WINDIR%\System32\Config\RegBack\`; Windows 10 versión 1803 y posteriores no rellenan automáticamente este directorio, a menos que esté habilitada la copia de seguridad periódica.<sup>[[34]](#references)[[35]](#references)</sup>
- En las versiones modernas de Windows, los datos de registro de clases y del shell por usuario también suelen almacenarse en `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`.<sup>[[34]](#references)[[66]](#references)</sup>

### Herramientas

Algunas herramientas son útiles para analizar hives del registro; confirma los formatos de hive y las versiones que admite cada herramienta antes de confiar en los resultados:

- **Registry Editor**: Está instalado en Windows. Es una GUI para navegar por el registro de Windows de la sesión actual.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite cargar el archivo del registro y recorrerlo mediante una GUI. También incluye marcadores que resaltan claves con información de interés.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): También tiene una GUI que permite navegar por el registro cargado e incluye plugins que resaltan información de interés en él.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Otra aplicación GUI capaz de extraer información de un hive del registro cargado.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recuperación de elementos eliminados

Las celdas eliminadas del hive pueden permanecer hasta que se reutilice su espacio, pero la recuperación depende del estado del hive y del analizador; trata las claves eliminadas recuperadas como pruebas que requieren validación, no como registros garantizados.

### Hora de última escritura

Las claves del registro tienen una marca de tiempo de última escritura; Windows la expone para la clave o cualquiera de sus entradas de valor, por lo que un valor no necesariamente tiene su propia marca de tiempo de modificación independiente.<sup>[[69]](#references)</sup>

### SAM

El hive **SAM** contiene datos de cuentas de usuarios y grupos locales, incluidos hashes de contraseñas protegidos por el material de la boot key del sistema.<sup>[[38]](#references)[[39]](#references)</sup>

En `SAM\Domains\Account\Users` puedes obtener identificadores de cuenta y algunos campos de inicio de sesión y directivas. La extracción de hashes sin conexión también requiere el hive `SYSTEM` para recuperar el material pertinente de la boot key.<sup>[[38]](#references)[[39]](#references)</sup>

### Entradas de interés en el Registro de Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programas ejecutados

### Procesos básicos de Windows

Se conserva una [publicación sobre procesos comunes de Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) como lectura adicional; corrobora cualquier afirmación sobre el comportamiento de los procesos con la documentación actual de Windows y las pruebas locales.<sup>[[2]](#references)</sup>

### Aplicaciones recientes de Windows

En las versiones de Windows 10 que lo exponen, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` contiene subclaves por aplicación con campos como la hora del último uso y el número de inicios; este artefacto se eliminó en versiones posteriores, así que valida la compilación objetivo.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

En los sistemas que exponen Background Activity Moderator, inspecciona la ruta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` o la ruta más reciente `...\bam\State\UserSettings\{SID}`. Los valores se organizan por SID de usuario y pueden contener rutas de ejecutables supervisados y datos de ejecución similares a FILETIME; el artefacto depende de la versión y debe corroborarse con otras pruebas.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch almacena en caché recursos y metadatos de inicio para que los programas puedan iniciarse más rápido.

Los archivos Prefetch se almacenan como archivos `.pf` en `C:\Windows\Prefetch`; el formato, la retención y los límites de cantidad de archivos varían según la versión de Windows. Microsoft documenta la retención de las últimas ocho horas de ejecución y hasta 1024 archivos en Windows 8 y versiones posteriores, por lo que no se deben generalizar los resúmenes antiguos sobre límites fijos.<sup>[[13]](#references)</sup>

El nombre del archivo suele seguir el formato `{program_name}-{hash}.pf`, donde el hash se deriva del contexto de ejecución, como la ruta y los argumentos; Windows 10 y versiones posteriores pueden comprimir el archivo. Su presencia es una prueba útil de ejecución, pero no demuestra por sí sola que lo haya ejecutado un usuario y debe corroborarse con otros artefactos.<sup>[[13]](#references)</sup>

Para inspeccionar estos archivos puedes usar [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), que documenta el análisis de directorios, la salida CSV/HTML y la compatibilidad con la descompresión de los archivos Prefetch aplicables de Windows 10.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** complementa Prefetch al usar patrones históricos de uso para mejorar la carga. En los sistemas que los generan, sus archivos de base de datos suelen encontrarse en `C:\Windows\Prefetch\Ag*.db`; el formato y su presencia dependen de la versión.<sup>[[41]](#references)</sup>

Estas bases de datos pueden contener nombres de aplicaciones, recuentos de uso, archivos o volúmenes a los que se accedió, rutas y rangos de tiempo, pero no deben considerarse un registro exacto de ejecución.<sup>[[41]](#references)</sup>

Se conserva el enlace existente a [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) como posible analizador; antes de usarlo, verifica su disponibilidad actual y los formatos de salida compatibles en la documentación de la herramienta.

### SRUM

**System Resource Usage Monitor** (SRUM) registra el uso de recursos por parte de aplicaciones y usuarios. Se introdujo en Windows 8 y almacena datos en la base de datos ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Proporciona la siguiente información:

- AppID y Path
- Usuario/SID asociado al registro
- Bytes enviados
- Bytes recibidos
- Interfaz de red
- Duración de la conexión
- Duración del proceso

La frecuencia de recopilación y la retención dependen de la implementación; no supongas que cada registro representa un intervalo exacto de ejecución de 60 minutos.<sup>[[13]](#references)</sup>

Puedes extraer y revisar los datos con [**srum_dump**](https://github.com/MarkBaggett/srum-dump), usando las opciones documentadas para la versión actual de la herramienta.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, también conocido como **ShimCache**, forma parte de la infraestructura de compatibilidad de aplicaciones de Windows y registra metadatos de archivos para tomar decisiones de compatibilidad. La ruta de la hive, el formato de los registros, la capacidad retenida y los campos varían según la versión de Windows; en las versiones modernas de Windows, ShimCache por sí solo no puede demostrar que un usuario haya ejecutado un archivo. Analiza la hive `SYSTEM` pertinente con la herramienta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) y corrobora sus resultados con artefactos de ejecución.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Para analizar la información almacenada, se recomienda usar la herramienta AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

El archivo **Amcache.hve** es una hive del registro que inventaría aplicaciones y archivos observados por Windows. Normalmente se encuentra en `C:\Windows\AppCompat\Programs\Amcache.hve`.

Puede contener entradas de archivos asociadas y no asociadas, rutas y valores SHA1, pero su presencia constituye evidencia de inventario y no demuestra por sí sola que se haya ejecutado un proceso.<sup>[[13]](#references)[[44]](#references)</sup>

Para extraer y analizar **Amcache.hve**, usa la herramienta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Este comando analiza la hive y escribe los resultados en formato CSV.<sup>[[44]](#references)</sup>

Por ejemplo:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Entre los archivos CSV generados, `Amcache_Unassociated file entries` puede ser útil al investigar archivos que no están asociados a un programa reconocido.<sup>[[44]](#references)</sup>

### RecentFileCache

En sistemas Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` puede contener información sobre binarios observados recientemente; su disponibilidad y semántica dependen de la versión.

Puedes usar [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) para analizar el archivo.<sup>[[45]](#references)</sup>

### Tareas programadas

La evidencia de tareas programadas puede encontrarse en `C:\Windows\System32\Tasks` para las tareas modernas y en `C:\Windows\Tasks` en archivos `.job` para las tareas heredadas; inspecciona el formato de definición de tareas adecuado para el sistema operativo.<sup>[[73]](#references)[[74]](#references)</sup>

### Servicios

La base de datos del Service Control Manager se encuentra en `SYSTEM\CurrentControlSet\Services` (si se trata de un hive SYSTEM sin conexión, inspecciona la clave de control correspondiente); contiene la configuración de servicios y controladores, como las rutas de los ejecutables y los tipos de inicio.<sup>[[72]](#references)</sup>

### **Windows Store**

Las aplicaciones instaladas de Windows Store pueden aparecer en `\ProgramData\Microsoft\Windows\AppRepository\`, incluida la base de datos **`StateRepository-Machine.srd`**. El esquema y las rutas varían según la versión de Windows.<sup>[[71]](#references)</sup>

La base de datos puede contener identificadores de aplicaciones, números de paquete y nombres para mostrar. Las discontinuidades en los identificadores no prueban, por sí solas, que se haya desinstalado una aplicación; corrobóralas con el estado del paquete y del registro.

Los registros de paquetes también pueden aparecer en `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft documenta una subclave `Deprovisioned` específica de ciertas versiones para las aplicaciones aprovisionadas que se quitaron; no des por sentado que existe una subclave `Deleted` en todas las compilaciones.<sup>[[70]](#references)</sup>

## Eventos de Windows

Según el proveedor, los eventos de Windows pueden contener:

- Qué ocurrió
- Una marca de tiempo `TimeCreated`, que debe interpretarse según el esquema del evento y el contexto horario del host
- Los usuarios implicados
- Los hosts implicados (nombre de host, IP)
- Los recursos a los que se accedió (archivos, carpetas, impresoras o servicios).<sup>[[49]](#references)</sup>

Antes de Windows Vista, los registros de eventos solían usar el formato binario heredado en `C:\Windows\System32\config`; Vista y las versiones posteriores usan el formato Windows Event Log, normalmente en `C:\Windows\System32\winevt\Logs`, con archivos `.evtx` que contienen datos de eventos representados en XML.<sup>[[46]](#references)[[47]](#references)</sup>

El registro SYSTEM guarda la configuración de los canales en **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, incluida la ruta del archivo configurada y los ajustes de retención.<sup>[[47]](#references)</sup>

Se pueden consultar con Windows Event Viewer (**`eventvwr.msc`**) o con herramientas como [**Event Log Explorer**](https://eventlogxp.com) y [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Comprender el registro de eventos de seguridad de Windows

En Vista y versiones posteriores, el canal Security suele almacenarse en `C:\Windows\System32\winevt\Logs\Security.evtx`. Su tamaño máximo y su política de retención se pueden configurar; con el registro circular, los registros más antiguos pueden sobrescribirse cuando el archivo alcanza su límite. El canal puede registrar eventos de autenticación, cierre de sesión, privilegios, directivas de auditoría y acceso a objetos cuando está habilitada la auditoría correspondiente.<sup>[[46]](#references)[[47]](#references)</sup>

### ID de evento clave para la autenticación de usuarios:

- **Event ID 4624**: Inicio de sesión correcto en una cuenta.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Inicio de sesión fallido en una cuenta.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Se terminó una sesión de inicio de sesión.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Un usuario inició un cierre de sesión.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Se asignaron privilegios especiales a un nuevo inicio de sesión; esto es habitual en cuentas de sistema y de administrador, por lo que no demuestra por sí solo una actividad maliciosa.<sup>[[54]](#references)</sup>

#### Tipos de inicio de sesión registrados habitualmente en 4624, 4625, 4634 y 4647:

- **Interactive (2)**: Inicio de sesión local interactivo.
- **Network (3)**: Acceso a un recurso compartido.
- **Batch (4)**: Inicio de sesión de un proceso por lotes.
- **Service (5)**: Inicio de sesión de un servicio.
- **Unlock (7)**: Desbloqueo de una estación de trabajo.
- **NetworkCleartext (8)**: Inicio de sesión de red que proporciona credenciales en texto claro al paquete de autenticación.
- **NewCredentials (9)**: Inicio de sesión que usa credenciales alternativas proporcionadas para conexiones salientes.
- **RemoteInteractive (10)**: Inicio de sesión mediante Remote Desktop o Terminal Services.
- **CachedInteractive (11)**: Inicio de sesión interactivo que usa credenciales de dominio almacenadas en caché.
- **CachedRemoteInteractive (12)**: Inicio de sesión remoto interactivo almacenado en caché.
- **CachedUnlock (13)**: Desbloqueo que usa credenciales almacenadas en caché.<sup>[[50]](#references)[[51]](#references)</sup>

#### Códigos Status y Sub Status para EventID 4625:

- **0xC0000064**: No existe ese usuario.
- **0xC000006A**: El nombre de usuario es correcto, pero la contraseña es incorrecta.
- **0xC0000234**: Cuenta bloqueada.
- **0xC0000072**: Cuenta deshabilitada.
- **0xC000006F**: Inicio de sesión fuera del horario permitido.
- **0xC0000070**: Incumplimiento de una restricción de estación de trabajo.
- **0xC0000193**: Cuenta caducada.
- **0xC0000071**: Contraseña caducada.
- **0xC0000133**: La diferencia horaria entre el cliente y el servidor es demasiado grande.
- **0xC0000224**: La cuenta debe cambiar su contraseña.
- **0xC0000225**: `STATUS_NOT_FOUND`; el código, por sí solo, no identifica un error del sistema ni un ataque.
- **0xC000015B**: No se concede a la cuenta el tipo de inicio de sesión solicitado.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Cambio de hora**: Se cambió la hora del sistema. Muchos eventos reflejan ajustes rutinarios del servicio de hora, por lo que debes correlacionar el actor y la fuente horaria antes de considerarlo una manipulación.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 y 6009:

- **Contexto de energía y servicios**: El evento 12 registra el inicio del sistema operativo; el 13, su apagado; el 1074, un apagado o reinicio planificado; el 6008 indica un apagado inesperado; y el 6009 registra la versión de Windows durante el arranque. Los eventos 6005 y 6006 indican, respectivamente, que el servicio Event Log se inició y se detuvo; por sí solos, no prueban el inicio y el apagado del sistema operativo.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Eliminación de registros**: El evento 1102 registra que se borró el registro de auditoría Security; investiga el actor y los eventos cercanos en lugar de dar por sentada su intención basándote solo en este evento.<sup>[[62]](#references)</sup>

#### EventIDs para el seguimiento de dispositivos USB:

- **20001 / 20003**: Eventos de instalación de dispositivos `UserPnp` que pueden ayudar a establecer la primera utilización o la actividad de instalación.
- **10000 / 10100**: Eventos de `DriverFrameworks-UserMode` que pueden acompañar la actividad de dispositivos.
- **Event ID 112**: La actividad de `DeviceSetupManager/Admin` puede proporcionar marcas de tiempo relacionadas con la conexión.
- El proveedor, el canal y la semántica de los eventos varían según la versión de Windows; inspecciona el nombre del proveedor y la carga útil del evento antes de asignarle un significado.<sup>[[59]](#references)</sup>

Para ver ejemplos prácticos de los tipos de inicio de sesión y el material de credenciales asociado, consulta la [guía detallada de Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Los detalles del evento, incluidos el tipo de inicio de sesión, el estado, el subestado, la dirección de origen y los campos del proceso, aportan contexto para Event ID 4625; un código de estado o un patrón de fallos repetidos es una pista para investigar, no una conclusión.<sup>[[51]](#references)[[55]](#references)</sup>

### Recuperar eventos de Windows

Como los registros de eventos suelen ser circulares, puede que los registros sobrescritos por el registrador no se puedan recuperar. Conserva una imagen forense o una copia de trabajo antes de interactuar con un sistema activo; utiliza un analizador o una herramienta de carving validada, como **Bulk_extractor**, solo después de confirmar que la versión de la herramienta es compatible con los datos `.evtx` de destino, y no desconectes un sistema en funcionamiento únicamente para intentar recuperar eventos.<sup>[[46]](#references)</sup>

### Identificar ataques comunes mediante eventos de Windows

Para consultar una referencia práctica de los ID de evento, visita el enlace existente de [Red Team Recipe](https://redteamrecipe.com/event-codes/) y valida sus ejemplos con la documentación de los proveedores mencionada anteriormente.

#### Ataques de fuerza bruta

Correlaciona los fallos repetidos de Event ID 4625 con un éxito posterior de 4624, el tipo de inicio de sesión, el estado, el origen y el contexto de la cuenta; la secuencia es un indicio que debe investigarse, no una prueba de un ataque.<sup>[[50]](#references)[[51]](#references)</sup>

#### Cambio de hora

Event ID 4616 registra los cambios en la hora del sistema, que pueden complicar el análisis de la cronología; compáralo con la evidencia del servicio de hora y del host.<sup>[[56]](#references)</sup>

#### Seguimiento de dispositivos USB

Los ID de eventos USB dependen del proveedor; correlaciona `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 y `DeviceSetupManager/Admin` 112 con los artefactos de SetupAPI y del registro.<sup>[[17]](#references)[[59]](#references)</sup>

#### Eventos de energía del sistema

Usa 12/13/1074/6008/6009 para obtener contexto sobre el inicio, el apagado, el reinicio y los cortes inesperados de energía del sistema operativo; 6005/6006 marcan el inicio y la detención del servicio Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Eliminación de registros

Security Event ID 1102 registra que se borró el registro de auditoría Security y debe correlacionarse con la cuenta y el proceso responsables.<sup>[[62]](#references)</sup>



## References

- [1] [Limpieza de Plug and Play de Windows](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigación de procesos comunes de Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Una perspectiva forense digital de las notificaciones de Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Herramientas forenses de Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier y flujos de datos alternativos](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Servicio Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operaciones de copia de seguridad y restauración del registro con VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Claves del registro para copias de seguridad y restauración](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problema de rendimiento de Word en la ubicación de AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Manual de respuesta a incidentes](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: formato de archivo binario Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Forense de USB MTP: identificación de artefactos de exfiltración de datos](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Entradas del registro de instalación de dispositivos SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID y tipos relacionados](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Buscar y transferir archivos de datos de Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Activar el modo caché de Exchange](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Solo se sincroniza un subconjunto de elementos](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configurar límites de tamaño para archivos de datos de Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Perfiles: dónde almacena Thunderbird los datos de usuario](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Configuración de cuentas de Thunderbird y directorios mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interfaz IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Hives del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [El registro del sistema no se respalda en RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Recuperación del registro de Windows](https://www.mitec.cz/wrr.html)
- [38] [Editar el registro de forma remota](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Descripción técnica de las contraseñas](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Evidencia de Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Formato de archivo de Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
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
- [58] [Solucionar problemas de apagado en curso](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forense de dispositivos de almacenamiento USB en Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Tipos de inicio de sesión de Windows explicados](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Evento 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderador de actividad en segundo plano](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registro - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [La impresión rápida deja de imprimir archivos adjuntos PDF en Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Archivos del registro de Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Evitar que las aplicaciones quitadas vuelvan durante una actualización](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: resultados de las pruebas de FTK y Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Base de datos de servicios instalados](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tareas](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Las tareas programadas fallan con el error «El servicio Task Scheduler no está disponible»](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Exploración de la base de datos de Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: formato de mensajes de Internet](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Administrar Recall para clientes de Windows](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
