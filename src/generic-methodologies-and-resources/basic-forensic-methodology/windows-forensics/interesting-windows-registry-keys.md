# Claves interesantes del Registro de Windows

{{#include ../../../banners/hacktricks-training.md}}

Las colmenas del Registro de Windows son una de las formas más rápidas de pasar de _¿qué ocurrió?_ a _¿qué usuario, cuándo y desde dónde?_. Para el análisis en vivo, prefiere `CurrentControlSet`; para el análisis offline de una colmena, primero determina qué `ControlSet00x` estaba activo en lugar de asumir `ControlSet001`.

### Información de la versión de Windows y del propietario

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edición/compilación de Windows, hora de instalación, propietario registrado, nombre del producto y otros metadatos de la compilación.
- `SYSTEM\Select`: asigna `Current`, `Default` y `LastKnownGood` a los valores reales de `ControlSet00x` utilizados por el sistema.

### Nombre del equipo

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname actual.

### Configuración de la zona horaria

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: zona horaria configurada y valores relacionados con el horario de verano.

### Seguimiento de tiempos de acceso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica si se están actualizando las marcas de tiempo del último acceso de NTFS.
- Para habilitarlo, usa: `fsutil behavior set disablelastaccess 0`

### Detalles del apagado

- `SYSTEM\CurrentControlSet\Control\Windows`: hora del último apagado.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: los sistemas antiguos también pueden mostrar contadores de apagado.

### Configuración de red

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs de la interfaz, leases DHCP, datos de gateway y DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nombre/SSID del perfil de red, además de las horas de la primera y última conexión.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` y `...\Unmanaged\{GUID}`: datos de correlación del perfil, como la dirección MAC del gateway y el sufijo DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: carpetas compartidas locales publicadas por el host.

### Acceso remoto e historial de recursos compartidos de red

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: lista MRU de RDP saliente (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historial de RDP saliente por host. Las subclaves suelen almacenar `UsernameHint`, y la hora de `LastWrite` de la clave es un pivot útil.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unidades de red asignadas, recursos compartidos UNC y puntos de montaje de medios extraíbles vinculados a un usuario específico.

### Programas que se inician automáticamente y persistencia programada

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` y `...\Tasks\{GUID}`: metadatos de tareas programadas. Si existe una tarea aquí, pero falta el valor `SD` en `Tree\<TaskName>`, sospecha una manipulación de tareas al estilo Tarrask y correlaciónala con `C:\Windows\System32\Tasks\<TaskName>`.

### Búsquedas, rutas introducidas y MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: términos de búsqueda del File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: rutas de Explorer introducidas manualmente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: los últimos 26 comandos de `Win + R`. `MRUList` conserva su orden.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documentos y carpetas abiertos recientemente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: archivos recientes de Office.

### Seguimiento de la actividad del usuario

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historial de ejecución iniciada mediante la GUI. Los nombres de los valores están codificados con ROT13 y los datos binarios incluyen contadores de ejecución y la hora de la última ejecución.<sup>[[1]](#references)</sup>
- Considera `UserAssist` como evidencia de apoyo sólida, no como una conclusión independiente: principalmente realiza el seguimiento de aplicaciones o archivos `.lnk` iniciados mediante Explorer y puede omitir ejecuciones desde la línea de comandos o mediante servicios. En Windows 10+, algunas entradas no implican necesariamente que el proceso se haya ejecutado por completo.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` y `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: rastros de ejecución modernos de Windows 10/11 con atribución mediante SID y hora de la última ejecución. Son especialmente útiles para binarios ejecutados localmente, pero las entradas antiguas pueden desaparecer rápidamente y las ejecuciones desde recursos compartidos de red o medios extraíbles son menos fiables.
- Para obtener artefactos de ejecución más amplios, como Prefetch, Amcache, ShimCache y SRUM, consulta la [descripción general de Windows forensics](README.md#programs-executed).

### Shellbags

- Los Shellbags se almacenan tanto en `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` como en `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Las entradas de `NTUSER.DAT` son especialmente útiles para la navegación UNC/de red, mientras que `UsrClass.dat` es donde Windows Vista+ suele almacenar los Shellbags de carpetas locales/extraíbles.
- Pueden mostrar la existencia, el recorrido y las preferencias de visualización de carpetas incluso después de que la carpeta se haya eliminado. El acceso a archivos de archivo mediante Explorer también puede dejar rastros de Shellbags.<sup>[[1]](#references)</sup>
- No todos los Shellbags demuestran un acceso correcto a una carpeta, por lo que debes corroborarlos con LNKs, Jump Lists, marcas de tiempo o asignaciones de volúmenes.
- Usa **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** o **SBECmd** para analizarlos.

### Información USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventario principal de dispositivos USB de almacenamiento masivo (proveedor, producto, revisión, número de serie/instancia del dispositivo).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventario más amplio de dispositivos USB, incluidos los dispositivos que no son de almacenamiento.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: en las compilaciones recientes de Windows 10/11, este es un punto de gran valor para obtener marcas de tiempo del ciclo de vida por dispositivo, como instalación, primera instalación, última conexión y última retirada.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: asigna volúmenes e identificadores de dispositivos a letras de unidad / GUIDs de volumen. Es posible que solo se conserve la última asignación para una letra de unidad determinada.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot útil para números de serie de volúmenes y metadatos de medios anteriores.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historial de interacción específico del usuario con letras de unidad y recursos compartidos.<sup>[[2]](#references)</sup>
- Los teléfonos y tablets modernos conectados mediante MTP/PTP pueden **no** aparecer en `USBSTOR`. Comprueba también `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` y `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Para vincular un dispositivo a un usuario, realiza un pivot desde los identificadores del dispositivo o del volumen hacia artefactos por usuario, como Shellbags, LNKs, Jump Lists, `RecentDocs` y `MountPoints2`.<sup>[[2]](#references)</sup>

## Referencias

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
