# Claves de registro de Windows interesantes

## Claves de registro de información del sistema Windows

### Versión

* **`Software\Microsoft\Windows NT\CurrentVersion`**: versión de Windows, Service Pack, hora de instalación y propietario registrado.

### Nombre de host

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Nombre de host.

### Zona horaria

* **`System\ControlSet001\Control\TimeZoneInformation`**: Zona horaria.

### Último tiempo de acceso

* **`System\ControlSet001\Control\Filesystem`**: Último tiempo de acceso (por defecto está desactivado con `NtfsDisableLastAccessUpdate=1`, si es `0`, entonces está habilitado).
  * Para habilitarlo: `fsutil behavior set disablelastaccess 0`

### Tiempo de apagado

* `System\ControlSet001\Control\Windows`: Tiempo de apagado.
* `System\ControlSet001\Control\Watchdog\Display`: Conteo de apagados (solo XP).

### Información de red

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Interfaces de red.
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: Primera y última vez que se realizó una conexión de red y conexiones a través de VPN.
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (para XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Tipo de red (0x47-inalámbrica, 0x06-cable, 0x17-3G) y categoría (0-Pública, 1-Privada/Hogar, 2-Dominio/Trabajo) y últimas conexiones.

### Carpetas compartidas

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Carpetas compartidas y sus configuraciones. Si la **Caché del lado del cliente** (CSCFLAGS) está habilitada, entonces se guardará una copia de los archivos compartidos en los clientes y en el servidor en `C:\Windows\CSC`.
  * CSCFlag=0 -> Por defecto, el usuario debe indicar los archivos que desea almacenar en caché.
  * CSCFlag=16 -> Almacenamiento en caché automático de documentos. "Todos los archivos y programas que los usuarios abren desde la carpeta compartida están automáticamente disponibles sin conexión" con la opción "optimizar para el rendimiento" desmarcada.
  * CSCFlag=32 -> Como las opciones anteriores, pero con la opción "optimizar para el rendimiento" marcada.
  * CSCFlag=48 -> La caché está deshabilitada.
  * CSCFlag=2048: Esta configuración solo está en Win 7 y 8 y es la configuración predeterminada hasta que deshabilite "Uso compartido simple de archivos" o use la opción de uso compartido "avanzada". También parece ser la configuración predeterminada para el "Grupo Hogar".
  * CSCFlag=768 -> Esta configuración solo se vio en dispositivos de impresión compartidos.

### Programas de inicio automático

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Búsquedas de explorador

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Word
