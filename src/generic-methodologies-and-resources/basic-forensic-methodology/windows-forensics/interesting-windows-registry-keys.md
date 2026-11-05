# Claves interesantes del Registro de Windows

{{#include ../../../banners/hacktricks-training.md}}

Las colmenas del Registro de Windows son una de las formas más rápidas de pasar de _¿qué ocurrió?_ a _¿qué usuario, cuándo y desde dónde?_. Para el análisis en vivo, prefiere `CurrentControlSet`; para analizar colmenas sin conexión, primero determina qué `ControlSet00x` estaba activo en lugar de asumir `ControlSet001`.

### Versión de Windows e información del propietario

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edición/compilación de Windows, hora de instalación, propietario registrado, nombre del producto y otros metadatos de la compilación.
- `SYSTEM\Select`: asigna `Current`, `Default` y `LastKnownGood` a los valores reales de `ControlSet00x` que usa el sistema.

### Nombre del equipo

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: nombre de host actual.

### Configuración de zona horaria

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: zona horaria configurada y valores relacionados con el horario de verano.

### Seguimiento de horas de acceso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica si se actualizan las marcas de tiempo del último acceso de NTFS.
- Para habilitarlo, usa: `fsutil behavior set disablelastaccess 0`

### Detalles del apagado

- `SYSTEM\CurrentControlSet\Control\Windows`: hora del último apagado.
- Los sistemas más antiguos también pueden exponer contadores de apagado en `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Configuración de red

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP de las interfaces, concesiones DHCP y datos de puerta de enlace y DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nombre/SSID del perfil de red, además de las horas de la primera y la última conexión.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` y `...\Unmanaged\{GUID}`: datos para correlacionar perfiles, como la dirección MAC de la puerta de enlace y el sufijo DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: carpetas compartidas locales publicadas por el host.

### Acceso remoto e historial de recursos compartidos de red

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: lista MRU de conexiones RDP salientes (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historial de RDP saliente por host. Las subclaves suelen almacenar `UsernameHint`, y la hora `LastWrite` de la clave es un punto de pivote útil.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unidades de red asignadas, recursos compartidos UNC y puntos de montaje de medios extraíbles asociados a un usuario específico.

### Programas que se inician automáticamente y persistencia programada

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` y `...\Tasks\{GUID}`: metadatos de tareas programadas. Si existe una tarea aquí, pero falta el valor `SD` en `Tree\<TaskName>`, sospecha de manipulación oculta de tareas al estilo Tarrask y correlaciónala con `C:\Windows\System32\Tasks\<TaskName>`.

### Búsquedas, rutas escritas y MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: términos de búsqueda del Explorador de archivos.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: rutas del Explorador escritas manualmente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: los últimos 26 comandos de `Win + R`. `MRUList` conserva el orden.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documentos y carpetas abiertos recientemente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: archivos recientes de Office.

### Seguimiento de la actividad del usuario

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historial de ejecución iniciada mediante la interfaz gráfica. Los nombres de los valores están codificados con ROT13, y los datos binarios incluyen contadores de ejecución y la hora de la última ejecución.<sup>[[1]](#references)</sup>
- Considera `UserAssist` como evidencia de apoyo sólida, no como un veredicto definitivo: principalmente registra aplicaciones o archivos `.lnk` iniciados mediante el Explorador y puede pasar por alto ejecuciones desde la línea de comandos o como servicio. En Windows 10 y versiones posteriores, algunas entradas no necesariamente significan que el proceso se haya ejecutado por completo.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` y `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: rastros de ejecución en versiones modernas de Windows 10/11, con atribución por SID y hora de la última ejecución. Son especialmente útiles para binarios ejecutados localmente, pero las entradas antiguas pueden desaparecer rápidamente y las ejecuciones desde recursos compartidos de red o medios extraíbles son menos fiables.
- Para obtener más artefactos de ejecución, como Prefetch, Amcache, ShimCache y SRUM, consulta la [descripción general del análisis forense de Windows](./#programs-executed).

### Shellbags

- Los Shellbags se almacenan tanto en `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` como en `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Las entradas de `NTUSER.DAT` son especialmente útiles para la navegación por recursos compartidos/UNC, mientras que Windows Vista y versiones posteriores suelen almacenar los Shellbags de carpetas locales o extraíbles en `UsrClass.dat`.
- Pueden mostrar la existencia de carpetas, su recorrido y las preferencias de vista de carpeta, incluso después de que esta se haya eliminado. El acceso a archivos comprimidos desde el Explorador también puede dejar rastros de Shellbags.<sup>[[1]](#references)</sup>
- No todos los Shellbags demuestran que se accedió correctamente a una carpeta, así que corrobóralos con archivos LNK, Jump Lists, marcas de tiempo o asignaciones de volúmenes.
- Usa **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** o **SBECmd** para analizarlos.

### Información de USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventario principal de dispositivos de almacenamiento masivo USB (proveedor, producto, revisión, número de serie/instancia del dispositivo).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventario más amplio de dispositivos USB, incluidos los que no son de almacenamiento.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: en versiones recientes de Windows 10/11, es un lugar de gran valor para encontrar marcas de tiempo del ciclo de vida por dispositivo, como la instalación, la primera instalación, la última conexión y la última desconexión.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: asigna volúmenes e identificadores de dispositivos a letras de unidad / GUID de volumen. Es posible que solo se conserve la última asignación de una letra de unidad determinada.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: punto de pivote útil para números de serie de volúmenes y metadatos de medios anteriores.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historial de interacción del usuario con letras de unidad y recursos compartidos.<sup>[[2]](#references)</sup>
- Es posible que los teléfonos y tabletas modernos conectados mediante MTP/PTP **no** aparezcan en `USBSTOR`. Comprueba también `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` y `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Para vincular un dispositivo a un usuario, parte de los identificadores del dispositivo o del volumen y busca artefactos por usuario, como Shellbags, archivos LNK, Jump Lists, `RecentDocs` y `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Guía rápida de análisis forense del Registro de Windows 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Análisis forense de dispositivos USB en Windows 10 y 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
