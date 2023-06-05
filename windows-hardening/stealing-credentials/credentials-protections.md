# Protecciones de Credenciales de Windows

## Protecciones de Credenciales

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

El protocolo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) fue introducido en Windows XP y fue diseñado para ser utilizado con el protocolo HTTP para la autenticación. Microsoft tiene este protocolo **habilitado por defecto en múltiples versiones de Windows** (Windows XP - Windows 8.0 y Windows Server 2003 - Windows Server 2012), lo que significa que **las contraseñas en texto plano se almacenan en LSASS** (Local Security Authority Subsystem Service). **Mimikatz** puede interactuar con LSASS permitiendo a un atacante **recuperar estas credenciales** a través del siguiente comando:
```
sekurlsa::wdigest
```
Este comportamiento puede ser **desactivado/activado estableciendo en 1** el valor de _**UseLogonCredential**_ y _**Negotiate**_ en _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
Si estas claves del registro **no existen** o el valor es **"0"**, entonces WDigest será **desactivado**.
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protección LSA

Microsoft en **Windows 8.1 y posteriores** ha proporcionado protección adicional para LSA para **prevenir** que procesos no confiables puedan **leer su memoria** o inyectar código. Esto evitará que `mimikatz.exe sekurlsa:logonpasswords` funcione correctamente.\
Para **activar esta protección**, es necesario establecer el valor _**RunAsPPL**_ en _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ en 1.
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Es posible saltarse esta protección utilizando el controlador de Mimikatz, mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** es una nueva característica en Windows 10 (edición Enterprise y Education) que ayuda a proteger sus credenciales en una máquina de amenazas como el pass the hash. Esto funciona a través de una tecnología llamada Modo Seguro Virtual (VSM) que utiliza extensiones de virtualización de la CPU (pero no es una máquina virtual real) para proporcionar **protección a áreas de memoria** (puede escuchar esto referido como Seguridad Basada en Virtualización o VBS). VSM crea una "burbuja" separada para los **procesos** clave que están **aislados** de los procesos regulares del **sistema operativo**, incluso el kernel y **sólo procesos de confianza específicos pueden comunicarse con los procesos** (conocidos como **trustlets**) en VSM. Esto significa que un proceso en el sistema operativo principal no puede leer la memoria de VSM, incluso los procesos del kernel. La **Autoridad de Seguridad Local (LSA) es uno de los trustlets** en VSM además del proceso estándar **LSASS** que todavía se ejecuta en el sistema operativo principal para garantizar el soporte con los procesos existentes, pero realmente actúa como un proxy o stub para comunicarse con la versión en VSM asegurando que las credenciales reales se ejecuten en la versión en VSM y, por lo tanto, estén protegidas contra ataques. Credential Guard debe estar activado e implementado en su organización ya que no está habilitado por defecto.\
De [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard)\
Se puede encontrar más información y un script PS1 para habilitar Credential Guard [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

En este caso, **Mimikatz no puede hacer mucho para saltarse** esto y extraer los hashes de LSASS. Pero siempre se puede agregar su **SSP personalizado** y **capturar las credenciales** cuando un usuario intenta iniciar sesión en **texto claro**.\
Más información sobre [**SSP y cómo hacer esto aquí**](../active-directory-methodology/custom-ssp.md).

Credential Guard se puede **habilitar de diferentes maneras**. Para comprobar si se habilitó utilizando el registro, se puede verificar el valor de la clave _**LsaCfgFlags**_ en _**HKLM\System\CurrentControlSet\Control\LSA**_. Si el valor es **"1"**, está activo con bloqueo UEFI, si **"2"** está activo sin bloqueo y si **"0"** no está habilitado.\
Esto **no es suficiente para habilitar Credential Guard** (pero es un indicador fuerte).\
Se puede encontrar más información y un script PS1 para habilitar Credential Guard [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## Modo RestrictedAdmin de RDP

Con Windows 8.1 y Windows Server 2012 R2 se introdujeron nuevas características de seguridad. Una de esas características de seguridad es el _modo Restricted Admin para RDP_. Esta nueva característica de seguridad se introdujo para mitigar el riesgo de ataques de [pass the hash](https://blog.ahasayen.com/pass-the-hash/).

Cuando te conectas a un equipo remoto usando RDP, tus credenciales se almacenan en el equipo remoto al que te conectas mediante RDP. Por lo general, se utiliza una cuenta poderosa para conectarse a servidores remotos, y tener tus credenciales almacenadas en todos estos equipos es una amenaza de seguridad.

Usando el _modo Restricted Admin para RDP_, cuando te conectas a un equipo remoto usando el comando **mstsc.exe /RestrictedAdmin**, te autenticarás en el equipo remoto, pero **tus credenciales no se almacenarán en ese equipo remoto**, como lo habrían hecho en el pasado. Esto significa que si hay un malware o incluso un usuario malintencionado activo en ese servidor remoto, tus credenciales no estarán disponibles en ese servidor de escritorio remoto para que el malware las ataque.

Ten en cuenta que como tus credenciales no se están guardando en la sesión de RDP, si **intentas acceder a recursos de red**, tus credenciales no se utilizarán. **En su lugar se utilizará la identidad de la máquina**.

![](../../.gitbook/assets/ram.png)

De [aquí](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciales en caché

Las **credenciales de dominio** son utilizadas por los componentes del sistema operativo y son **autenticadas** por la **Autoridad de Seguridad Local** (LSA). Por lo general, las credenciales de dominio se establecen para un usuario cuando un paquete de seguridad registrado autentica los datos de inicio de sesión del usuario. Este paquete de seguridad registrado puede ser el protocolo **Kerberos** o **NTLM**.

**Windows almacena las últimas diez credenciales de inicio de sesión de dominio en caso de que el controlador de dominio se desconecte**. Si el controlador de dominio se desconecta, un usuario **todavía podrá iniciar sesión en su equipo**. Esta función es principalmente para usuarios de portátiles que no inician sesión regularmente en el dominio de su empresa. El número de credenciales que almacena el equipo se puede controlar mediante la siguiente **clave del registro o mediante directiva de grupo**:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Las credenciales están ocultas para los usuarios normales, incluso para las cuentas de administrador. El usuario **SYSTEM** es el único usuario que tiene **privilegios** para **ver** estas **credenciales**. Para que un administrador pueda ver estas credenciales en el registro, debe acceder al registro como usuario SYSTEM.\
Las credenciales en caché se almacenan en el registro en la siguiente ubicación del registro:
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
## Extrayendo de Mimikatz: `lsadump::cache`
Desde [aquí](http://juggernaut.wikidot.com/cached-credentials).

## Usuarios Protegidos

Cuando el usuario que ha iniciado sesión es miembro del grupo de Usuarios Protegidos, se aplican las siguientes protecciones:

* La delegación de credenciales (CredSSP) no almacenará en caché las credenciales en texto plano del usuario, incluso cuando la configuración de directiva de grupo **Permitir la delegación de credenciales predeterminadas** esté habilitada.
* A partir de Windows 8.1 y Windows Server 2012 R2, Windows Digest no almacenará en caché las credenciales en texto plano del usuario, incluso cuando Windows Digest esté habilitado.
* **NTLM** no almacenará en caché las credenciales en texto plano del usuario ni la función unidireccional NT (NTOWF).
* **Kerberos** ya no creará claves **DES** o **RC4**. Además, no almacenará en caché las credenciales en texto plano del usuario ni las claves a largo plazo después de que se adquiera el TGT inicial.
* No se creará un verificador en caché al iniciar sesión o desbloquear, por lo que ya no se admite el inicio de sesión sin conexión.

Después de que se agregue la cuenta de usuario al grupo de Usuarios Protegidos, la protección comenzará cuando el usuario inicie sesión en el dispositivo. **Desde** [**aquí**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Operadores de cuenta    | Operadores de cuenta     | Operadores de cuenta                                                          | Operadores de cuenta         |
| Administrador           | Administrador            | Administrador                                                                 | Administrador                |
| Administradores         | Administradores          | Administradores                                                               | Administradores              |
| Operadores de copia de seguridad | Operadores de copia de seguridad | Operadores de copia de seguridad | Operadores de copia de seguridad |
| Publicadores de certificados |                          |                                                                               |                              |
| Administradores de dominio | Administradores de dominio | Administradores de dominio                                                 | Administradores de dominio   |
| Controladores de dominio | Controladores de dominio  | Controladores de dominio                                                       | Controladores de dominio     |
| Administradores de empresa | Administradores de empresa | Administradores de empresa                                                 | Administradores de empresa   |
|                         |                          |                                                                               | Administradores de claves de empresa |
|                         |                          |                                                                               | Administradores de claves    |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Operadores de impresión | Operadores de impresión  | Operadores de impresión                                                       | Operadores de impresión      |
|                         |                          | Controladores de dominio de solo lectura                                       | Controladores de dominio de solo lectura |
| Replicador              | Replicador               | Replicador                                                                    | Replicador                   |
| Administradores de esquema | Administradores de esquema | Administradores de esquema                                                 | Administradores de esquema   |
| Operadores de servidor  | Operadores de servidor   | Operadores de servidor                                                        | Operadores de servidor       |

**Tabla desde** [**aquí**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
