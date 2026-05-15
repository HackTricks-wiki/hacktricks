# Claves interesantes del Registro de Windows

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives son una de las formas más rápidas de pasar de _¿qué pasó?_ a _¿qué usuario, cuándo y desde dónde?_. Para análisis en vivo, prefiere `CurrentControlSet`; para análisis offline de hives, primero resuelve qué `ControlSet00x` estaba activo en lugar de hardcodear `ControlSet001`.

### Versión de Windows e información del propietario

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edición/build de Windows, hora de instalación, propietario registrado, nombre del producto y otros metadatos de compilación.
- `SYSTEM\Select`: mapea `Current`, `Default` y `LastKnownGood` a los valores reales `ControlSet00x` usados por el sistema.

### Nombre del equipo

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname actual.

### Configuración de zona horaria

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: zona horaria configurada y valores relacionados con DST.

### Seguimiento de tiempo de acceso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica si se están actualizando las marcas de tiempo de último acceso de NTFS.
- Para activarlo, usa: `fsutil behavior set disablelastaccess 0`

### Detalles de apagado

- `SYSTEM\CurrentControlSet\Control\Windows`: hora del último apagado.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: en sistemas antiguos también puede exponer contadores de apagado.

### Configuración de red

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs de la interfaz, leases DHCP, gateway y datos DNS.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nombre del perfil de red/SSID más las horas de primera y última conexión.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` y `...\Unmanaged\{GUID}`: datos de correlación del perfil como la MAC del gateway y el sufijo DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: carpetas compartidas locales publicadas por el host.

### Acceso remoto e historial de recursos compartidos de red

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: lista MRU de RDP saliente (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historial de RDP saliente por host. Las subclaves suelen almacenar `UsernameHint`, y la hora `LastWrite` de la clave es un pivote útil.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unidades de red mapeadas, recursos compartidos UNC y puntos de montaje de medios extraíbles vinculados a un usuario específico.

### Programas que se inician automáticamente y persistencia programada

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` y `...\Tasks\{GUID}`: metadatos de tareas programadas. Si una tarea existe aquí pero el valor `SD` falta en `Tree\<TaskName>`, sospecha manipulación oculta de tareas al estilo Tarrask y correlaciónala con `C:\Windows\System32\Tasks\<TaskName>`.

### Búsquedas, rutas tecleadas y MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: términos de búsqueda de File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: rutas de Explorer escritas manualmente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: los últimos 26 comandos de `Win + R`. `MRUList` preserva su orden.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documentos y carpetas abiertas recientemente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: archivos recientes de Office.

### Seguimiento de actividad del usuario

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historial de ejecución impulsado por GUI. Los nombres de valor están codificados en ROT13, y los datos binarios incluyen contadores de ejecución y la hora de última ejecución.
- Trata `UserAssist` como evidencia de apoyo sólida, no como un veredicto aislado: principalmente rastrea apps o archivos `.lnk` lanzados a través de Explorer y puede omitir la ejecución por línea de comandos o por servicio. En Windows 10+, algunas entradas no significan necesariamente que el proceso se ejecutó por completo.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` y `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: trazas modernas de ejecución en Windows 10/11 con atribución por SID y hora de última ejecución. Son especialmente útiles para binarios ejecutados localmente, pero las entradas antiguas pueden caducar rápido y las ejecuciones desde recursos compartidos de red/medios extraíbles son menos fiables.
- Para artefactos de ejecución más amplios como Prefetch, Amcache, ShimCache y SRUM, consulta el [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags se almacenan tanto en `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` como en `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- Las entradas de `NTUSER.DAT` son especialmente útiles para navegación UNC/de red, mientras que `UsrClass.dat` es donde Windows Vista+ suele almacenar shellbags de carpetas locales o extraíbles.
- Pueden mostrar la existencia de carpetas, su recorrido y preferencias de vista incluso después de que la carpeta haya sido borrada. El acceso tipo Explorer a archivos de archivo también puede dejar rastros de shellbag.
- No todos los shellbags prueban acceso exitoso a la carpeta, así que corrobora con LNKs, Jump Lists, marcas de tiempo o mapeos de volumen.
- Usa **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** o **SBECmd** para analizarlos.

### Información USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventario principal de dispositivos USB de almacenamiento masivo (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventario más amplio de dispositivos USB, incluyendo dispositivos que no son de almacenamiento.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: en builds recientes de Windows 10/11 este es un punto de alto valor para marcas de tiempo de ciclo de vida por dispositivo como install, first install, last arrival y last removal.
- `HKLM\SYSTEM\MountedDevices`: mapea volúmenes e identificadores de dispositivo a letras de unidad / volume GUIDs. Solo puede sobrevivir el último mapeo para una letra de unidad dada.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivote útil para números de serie de volumen y metadatos previos del medio.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historial específico del usuario de interacción con letras de unidad y recursos compartidos.
- Los teléfonos y tablets modernos conectados vía MTP/PTP pueden **no** aparecer bajo `USBSTOR`. Revisa también `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` y `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Para vincular un dispositivo con un usuario, pivota desde identificadores de dispositivo o volumen hacia artefactos por usuario como shellbags, LNKs, Jump Lists, `RecentDocs` y `MountPoints2`.



## Referencias

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
