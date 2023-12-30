# Claves interesantes del Registro de Windows

## Claves interesantes del Registro de Windows

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Información del sistema Windows**

### Versión

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Versión de Windows, Service Pack, tiempo de instalación y el propietario registrado

### Nombre de host

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Nombre de host

### Zona horaria

* **`System\ControlSet001\Control\TimeZoneInformation`**: Zona horaria

### Último acceso

* **`System\ControlSet001\Control\Filesystem`**: Último acceso (por defecto está deshabilitado con `NtfsDisableLastAccessUpdate=1`, si es `0`, entonces, está habilitado).
* Para habilitarlo: `fsutil behavior set disablelastaccess 0`

### Tiempo de apagado

* `System\ControlSet001\Control\Windows`: Tiempo de apagado
* `System\ControlSet001\Control\Watchdog\Display`: Contador de apagados (solo XP)

### Información de red

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Interfaces de red
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: Primera y última vez que se realizó una conexión de red y conexiones a través de VPN
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (para XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Tipo de red (0x47-inalámbrica, 0x06-cable, 0x17-3G) y categoría (0-Pública, 1-Privada/Hogar, 2-Dominio/Trabajo) y últimas conexiones

### Carpetas compartidas

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Carpetas compartidas y sus configuraciones. Si **Client Side Caching** (CSCFLAGS) está habilitado, entonces, una copia de los archivos compartidos se guardará en los clientes y servidor en `C:\Windows\CSC`
* CSCFlag=0 -> Por defecto el usuario necesita indicar los archivos que quiere cachear
* CSCFlag=16 -> Caché automático de documentos. "Todos los archivos y programas que los usuarios abren desde la carpeta compartida están automáticamente disponibles sin conexión" con la opción "optimizar para rendimiento" desmarcada.
* CSCFlag=32 -> Como la opción anterior pero con "optimizar para rendimiento" marcada
* CSCFlag=48 -> Caché deshabilitado.
* CSCFlag=2048: Esta configuración solo está en Win 7 & 8 y es la configuración predeterminada hasta que deshabilitas "Compartir archivos simple" o usas la opción de compartir "avanzada". También parece ser la configuración predeterminada para el "Grupo en el hogar"
* CSCFlag=768 -> Esta configuración solo se vio en dispositivos de impresión compartidos.

### Programas de inicio automático

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Búsquedas en el Explorador

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: Lo que el usuario buscó usando el explorador/ayudante. El elemento con `MRU=0` es el último.

### Rutas escritas

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Rutas escritas en el explorador (solo W10)

### Documentos recientes

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: Documentos recientes abiertos por el usuario
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU`: Documentos recientes de Office. Versiones:
* 14.0 Office 2010
* 12.0 Office 2007
* 11.0 Office 2003
* 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU`: Documentos recientes de Office. Versiones:
* 15.0 office 2013
* 16.0 Office 2016

### MRUs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

Indica la ruta desde donde se ejecutó el ejecutable

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

Indica archivos abiertos dentro de una ventana abierta

### Últimos comandos ejecutados

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### Clave User Assist

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

El GUID es el id de la aplicación. Datos guardados:

* Última vez ejecutada
* Contador de ejecuciones
* Nombre de la aplicación GUI (esto contiene la ruta absoluta y más información)
* Tiempo de enfoque y nombre de enfoque

## Shellbags

Cuando abres un directorio, Windows guarda datos sobre cómo visualizar el directorio en el registro. Estas entradas se conocen como Shellbags.

Acceso al Explorador:

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Acceso al Escritorio:

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Para analizar los Shellbags puedes usar [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) y podrás encontrar el **tiempo MAC de la carpeta** y también la **fecha de creación y fecha de modificación del shellbag** que están relacionadas con la **primera vez y la última vez** que se accedió a la carpeta.

Nota 2 cosas de la siguiente imagen:

1. Sabemos el **nombre de las carpetas del USB** que se insertó en **E:**
2. Sabemos cuándo se **creó y modificó el shellbag** y cuándo se creó y accedió a la carpeta

![](<../../../.gitbook/assets/image (475).png>)

## Información de USB

### Información del dispositivo

El registro `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR` monitorea cada dispositivo USB que se ha conectado al PC.\
Dentro de este registro es posible encontrar:

* El nombre del fabricante
* El nombre y versión del producto
* El ID de Clase del Dispositivo
* El nombre del volumen (en las siguientes imágenes el nombre del volumen es la subclave resaltada)

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

Además, revisando el registro `HKLM\SYSTEM\ControlSet001\Enum\USB` y comparando los valores de las subclaves es posible encontrar el valor VID.

![](<../../../.gitbook/assets/image (478).png>)

Con la información anterior el registro `SOFTWARE\Microsoft\Windows Portable Devices\Devices` puede usarse para obtener el **`{GUID}`**:

![](<../../../.gitbook/assets/image (480).png>)

### Usuario que usó el dispositivo

Teniendo el **{GUID}** del dispositivo ahora es posible **revisar todas las colmenas NTUDER.DAT de todos los usuarios**, buscando el GUID hasta encontrarlo en una de ellas (`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`).

![](<../../../.gitbook/assets/image (481).png>)

### Último montado

Revisando el registro `System\MoutedDevices` es posible averiguar **cuál fue el último dispositivo montado**. En la siguiente imagen revisa cómo el último dispositivo montado en `E:` es el de Toshiba (usando la herramienta Registry Explorer).

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### Número de serie del volumen

En `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` puedes encontrar el número de serie del volumen. **Conociendo el nombre del volumen y el número de serie del volumen puedes correlacionar la información** de archivos LNK que usan esa información.

Nota que cuando un dispositivo USB es formateado:

* Se crea un nuevo nombre de volumen
* Se crea un nuevo número de serie del volumen
* Se mantiene el número de serie físico

### Timestamps

En `System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\` puedes encontrar la primera y última vez que se conectó el dispositivo:

* 0064 -- Primera conexión
* 0066 -- Última conexión
* 0067 -- Desconexión

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
