# Claves del Registro de Windows de Interés

## Claves del Registro de Windows de Interés

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Información del sistema Windows**

### Versión

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Versión de Windows, Service Pack, hora de instalación y propietario registrado

### Nombre de host

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Nombre de host

### Zona horaria

* **`System\ControlSet001\Control\TimeZoneInformation`**: Zona horaria

### Última hora de acceso

* **`System\ControlSet001\Control\Filesystem`**: Última hora de acceso (por defecto está deshabilitada con `NtfsDisableLastAccessUpdate=1`, si es `0`, entonces está habilitada).
* Para habilitarla: `fsutil behavior set disablelastaccess 0`

### Hora de apagado

* `System\ControlSet001\Control\Windows`: Hora de apagado
* `System\ControlSet001\Control\Watchdog\Display`: Conteo de apagados (solo XP)

### Información de red

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Interfaces de red
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: Primera y última vez que se realizó una conexión de red y conexiones a través de VPN
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (para XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Tipo de red (0x47-inalámbrica, 0x06-cable, 0x17-3G) y categoría (0-Pública, 1-Privada/Hogar, 2-Dominio/Trabajo) y últimas conexiones

### Carpetas compartidas

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Carpetas compartidas y sus configuraciones. Si está habilitado el **Caching del lado del cliente** (CSCFLAGS), entonces, una copia de los archivos compartidos se guardará en los clientes y en el servidor en `C:\Windows\CSC`
* CSCFlag=0 -> Por defecto, el usuario debe indicar los archivos que desea almacenar en caché
* CSCFlag=16 -> Almacenamiento automático de documentos en caché. "Todos los archivos y programas que los usuarios abren desde la carpeta compartida están automáticamente disponibles sin conexión" con la opción "optimizar para rendimiento" desmarcada.
* CSCFlag=32 -> Similar a las opciones anteriores pero con la opción "optimizar para rendimiento" marcada
* CSCFlag=48 -> La caché está deshabilitada.
* CSCFlag=2048: Esta configuración solo está en Win 7 y 8 y es la configuración predeterminada hasta que deshabilites "Compartir archivos simples" o uses la opción de uso compartido "avanzada". También parece ser la configuración predeterminada para el "Grupo Hogar"
* CSCFlag=768 -> Esta configuración solo se vio en dispositivos de impresión compartidos.

### Programas de inicio automático

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Búsquedas de Explorer

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: Lo que el usuario buscó usando el explorador/ayuda. El elemento con `MRU=0` es el último.

### Rutas escritas

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Rutas escritas en el explorador (solo W10)

### Documentos recientes

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: Documentos recientes abiertos por el usuario
* `NTUSER.DAT\Software\Microsoft\Office{Versión}{Excel|Word}\FileMRU`: Documentos de Office recientes. Versiones:
* 14.0 Office 2010
* 12.0 Office 2007
* 11.0 Office 2003
* 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Versión}{Excel|Word} UserMRU\LiveID_###\FileMRU`: Documentos de Office recientes. Versiones:
* 15.0 Office 2013
* 16.0 Office 2016

### MRUs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

Indica la ruta desde la cual se ejecutó el ejecutable

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

Indica archivos abiertos dentro de una ventana abierta

### Últimos comandos ejecutados

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### User AssistKey

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

El GUID es el id de la aplicación. Datos guardados:

* Última hora de ejecución
* Conteo de ejecuciones
* Nombre de la aplicación GUI (esto contiene la ruta absoluta y más información)
* Tiempo de enfoque y nombre de enfoque

## Shellbags

Cuando abres un directorio, Windows guarda datos sobre cómo visualizar el directorio en el registro. Estas entradas se conocen como Shellbags.

Acceso a Explorer:

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Acceso al Escritorio:

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Para analizar los Shellbags puedes usar [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) y podrás encontrar la\*\* hora MAC de la carpeta **y también la** fecha de creación y modificación del shellbag que están relacionadas con la\*\* primera vez y la última vez\*\* que se accedió a la carpeta.

Observa 2 cosas de la siguiente imagen:

1. Conocemos el **nombre de las carpetas del USB** que se insertó en **E:**
2. Sabemos cuándo se **creó y modificó el shellbag** y cuándo se creó y accedió a la carpeta

![](<../../../.gitbook/assets/image (475).png>)

## Información del USB

### Información del dispositivo

El registro `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR` monitorea cada dispositivo USB que se ha conectado a la PC.\
Dentro de este registro es posible encontrar:

* El nombre del fabricante
* El nombre y versión del producto
* El ID de clase del dispositivo
* El nombre del volumen (en las siguientes imágenes el nombre del volumen es la subclave resaltada)

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

Además, al verificar el registro `HKLM\SYSTEM\ControlSet001\Enum\USB` y comparar los valores de las subclaves, es posible encontrar el valor VID.

![](<../../../.gitbook/assets/image (478).png>)

Con la información anterior, el registro `SOFTWARE\Microsoft\Windows Portable Devices\Devices` se puede utilizar para obtener el **`{GUID}`**:

![](<../../../.gitbook/assets/image (480).png>)

### Usuario que utilizó el dispositivo

Teniendo el **{GUID}** del dispositivo, ahora es posible **verificar todas las colmenas NTUDER.DAT de todos los usuarios**, buscando el GUID hasta encontrarlo en uno de ellos (`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`).

![](<../../../.gitbook/assets/image (481).png>)

### Último montaje

Al verificar el registro `System\MoutedDevices` es posible descubrir **qué dispositivo fue el último montado**. En la siguiente imagen, verifica cómo el último dispositivo montado en `E:` es el de Toshiba (usando la herramienta Registry Explorer).

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### Número de serie del volumen

En `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` puedes encontrar el número de serie del volumen. **Conociendo el nombre del volumen y el número de serie del volumen puedes correlacionar la información** de los archivos LNK que utilizan esa información.

Ten en cuenta que cuando se formatea un dispositivo USB:

* Se crea un nuevo nombre de volumen
* Se crea un nuevo número de serie de volumen
* Se mantiene el número de serie físico

### Marcas de tiempo

En `System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\` puedes encontrar la primera y última vez que se conectó el dispositivo:

* 0064 -- Primera conexión
* 0066 -- Última conexión
* 0067 -- Desconexión

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
