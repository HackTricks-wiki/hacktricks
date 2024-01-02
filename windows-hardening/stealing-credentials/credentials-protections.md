# Protecciones de Credenciales de Windows

## Protecciones de Credenciales

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

El protocolo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) fue introducido en Windows XP y fue diseñado para ser utilizado con el Protocolo HTTP para autenticación. Microsoft tiene este protocolo **habilitado por defecto en múltiples versiones de Windows** (Windows XP — Windows 8.0 y Windows Server 2003 — Windows Server 2012), lo que significa que **las contraseñas en texto plano se almacenan en el LSASS** (Local Security Authority Subsystem Service). **Mimikatz** puede interactuar con el LSASS permitiendo a un atacante **recuperar estas credenciales** a través del siguiente comando:
```
sekurlsa::wdigest
```
Este comportamiento puede ser **desactivado/activado estableciendo en 1** el valor de _**UseLogonCredential**_ y _**Negotiate**_ en _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
Si estas claves del registro **no existen** o el valor es **"0"**, entonces WDigest estará **desactivado**.
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protección LSA

Microsoft en **Windows 8.1 y posteriores** ha proporcionado protección adicional para el LSA para **prevenir** que procesos no confiables puedan **leer su memoria** o inyectar código. Esto evitará que el comando regular `mimikatz.exe sekurlsa:logonpasswords` funcione correctamente.\
Para **activar esta protección** necesitas establecer el valor _**RunAsPPL**_ en _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ a 1.
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Evasión

Es posible evadir esta protección utilizando el driver de Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** es una nueva característica en Windows 10 (edición Enterprise y Education) que ayuda a proteger tus credenciales en una máquina contra amenazas como pass the hash. Esto funciona a través de una tecnología llamada Modo Seguro Virtual (VSM) que utiliza extensiones de virtualización de la CPU (pero no es una máquina virtual real) para proporcionar **protección a áreas de la memoria** (puede que escuches esto referido como Seguridad Basada en Virtualización o VBS). VSM crea una "burbuja" separada para **procesos** clave que están **aislados** de los procesos regulares del **sistema operativo**, incluso del kernel y **solo procesos de confianza específicos pueden comunicarse con los procesos** (conocidos como **trustlets**) en VSM. Esto significa que un proceso en el sistema operativo principal no puede leer la memoria de VSM, incluso los procesos del kernel. La **Autoridad de Seguridad Local (LSA) es uno de los trustlets** en VSM además del proceso **LSASS** estándar que aún se ejecuta en el sistema operativo principal para asegurar la compatibilidad con los procesos existentes, pero realmente solo actúa como un proxy o stub para comunicarse con la versión en VSM asegurando que las credenciales reales se ejecuten en la versión de VSM y, por lo tanto, estén protegidas de ataques. Para Windows 10, Credential Guard debe estar activado e implementado en tu organización ya que **no está habilitado por defecto.**
Desde [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard). Más información y un script PS1 para habilitar Credential Guard [se puede encontrar aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage). Sin embargo, a partir de Windows 11 Enterprise, versión 22H2 y Windows 11 Education, versión 22H2, los sistemas compatibles tienen Windows Defender Credential Guard [activado por defecto](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement).

En este caso **Mimikatz no puede hacer mucho para evadir** esto y extraer los hashes de LSASS. Pero siempre podrías agregar tu **SSP personalizado** y **capturar las credenciales** cuando un usuario intenta iniciar sesión en **texto claro**.\
Más información sobre [**SSP y cómo hacer esto aquí**](../active-directory-methodology/custom-ssp.md).

Credential Guard podría ser **habilitado de diferentes maneras**. Para verificar si se habilitó usando el registro, podrías revisar el valor de la clave _**LsaCfgFlags**_ en _**HKLM\System\CurrentControlSet\Control\LSA**_. Si el valor es **"1"**, entonces está activo con bloqueo UEFI, si **"2"** está activo sin bloqueo y si **"0"** no está habilitado.\
Esto **no es suficiente para habilitar Credential Guard** (pero es un fuerte indicador).\
Más información y un script PS1 para habilitar Credential Guard [se puede encontrar aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## Modo RestrictedAdmin de RDP

Con Windows 8.1 y Windows Server 2012 R2, se introdujeron nuevas características de seguridad. Una de esas características de seguridad es el _modo Restricted Admin para RDP_. Esta nueva característica de seguridad se introdujo para mitigar el riesgo de ataques de [pass the hash](https://blog.ahasayen.com/pass-the-hash/).

Cuando te conectas a un ordenador remoto usando RDP, tus credenciales se almacenan en el ordenador remoto al que te conectas mediante RDP. Normalmente estás utilizando una cuenta poderosa para conectarte a servidores remotos, y tener tus credenciales almacenadas en todos estos ordenadores es una amenaza de seguridad de hecho.

Usando el _modo Restricted Admin para RDP_, cuando te conectas a un ordenador remoto usando el comando, **mstsc.exe /RestrictedAdmin**, serás autenticado en el ordenador remoto, pero **tus credenciales no se almacenarán en ese ordenador remoto**, como lo habrían estado en el pasado. Esto significa que si un malware o incluso un usuario malicioso está activo en ese servidor remoto, tus credenciales no estarán disponibles en ese servidor de escritorio remoto para que el malware ataque.

Ten en cuenta que como tus credenciales no se guardan en la sesión de RDP, si **intentas acceder a recursos de red** tus credenciales no se utilizarán. **En su lugar se utilizará la identidad de la máquina**.

![](../../.gitbook/assets/ram.png)

Desde [aquí](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciales en Caché

Las **credenciales de dominio** son utilizadas por los componentes del sistema operativo y son **autenticadas** por la **Autoridad de Seguridad Local** (LSA). Típicamente, las credenciales de dominio se establecen para un usuario cuando un paquete de seguridad registrado autentica los datos de inicio de sesión del usuario. Este paquete de seguridad registrado puede ser el protocolo **Kerberos** o **NTLM**.

**Windows almacena las últimas diez credenciales de inicio de sesión de dominio en caso de que el controlador de dominio se desconecte**. Si el controlador de dominio se desconecta, un usuario **aún podrá iniciar sesión en su ordenador**. Esta característica es principalmente para usuarios de portátiles que no se conectan regularmente al dominio de su empresa. El número de credenciales que el ordenador almacena se puede controlar mediante la siguiente **clave de registro, o a través de política de grupo**:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Las credenciales están ocultas para los usuarios normales, incluso para las cuentas de administrador. El usuario **SYSTEM** es el único usuario que tiene **privilegios** para **ver** estas **credenciales**. Para que un administrador pueda ver estas credenciales en el registro, debe acceder al registro como usuario SYSTEM.
Las credenciales almacenadas en caché se guardan en el registro en la siguiente ubicación del registro:
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**Extracción desde Mimikatz**: `lsadump::cache`\
Desde [aquí](http://juggernaut.wikidot.com/cached-credentials).

## Usuarios Protegidos

Cuando el usuario conectado es miembro del grupo de Usuarios Protegidos, se aplican las siguientes protecciones:

* La delegación de credenciales (CredSSP) no almacenará las credenciales en texto plano del usuario, incluso cuando la configuración de la Política de Grupo **Permitir la delegación de credenciales predeterminadas** esté habilitada.
* A partir de Windows 8.1 y Windows Server 2012 R2, Windows Digest no almacenará las credenciales en texto plano del usuario, incluso cuando Windows Digest esté habilitado.
* **NTLM** no almacenará en caché las credenciales en **texto plano** del usuario o la función **unidireccional** de NT (NTOWF).
* **Kerberos** ya no creará claves **DES** o **RC4**. Además, no almacenará en caché las credenciales en texto plano del usuario o las claves a largo plazo después de que se adquiera el TGT inicial.
* **No se crea un verificador en caché al iniciar sesión o desbloquear**, por lo que el inicio de sesión sin conexión ya no es compatible.

Después de que la cuenta de usuario se añade al grupo de Usuarios Protegidos, la protección comenzará cuando el usuario inicie sesión en el dispositivo. **Desde** [**aquí**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Controladores de dominio de solo lectura                                      | Controladores de dominio de solo lectura |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

**Tabla desde** [**aquí**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
