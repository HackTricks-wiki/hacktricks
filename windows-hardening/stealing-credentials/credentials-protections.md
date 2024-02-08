# Protecciones de Credenciales de Windows

## Protecciones de Credenciales

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## WDigest

El protocolo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396), introducido con Windows XP, está diseñado para la autenticación a través del Protocolo HTTP y está **habilitado de forma predeterminada en Windows XP hasta Windows 8.0 y Windows Server 2003 hasta Windows Server 2012**. Esta configuración predeterminada resulta en **almacenamiento de contraseñas en texto plano en LSASS** (Servicio de Subsistema de Autoridad de Seguridad Local). Un atacante puede usar Mimikatz para **extraer estas credenciales** ejecutando:
```bash
sekurlsa::wdigest
```
Para **activar o desactivar esta función**, las claves del registro _**UseLogonCredential**_ y _**Negotiate**_ dentro de _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ deben establecerse en "1". Si estas claves están **ausentes o establecidas en "0"**, WDigest está **deshabilitado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protección de LSA

A partir de **Windows 8.1**, Microsoft mejoró la seguridad de LSA para **bloquear lecturas de memoria no autorizadas o inyecciones de código por procesos no confiables**. Esta mejora dificulta el funcionamiento típico de comandos como `mimikatz.exe sekurlsa:logonpasswords`. Para **habilitar esta protección mejorada**, el valor _**RunAsPPL**_ en _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ debe ajustarse a 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Salto

Es posible saltarse esta protección utilizando el controlador Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Guardia de Credenciales

**Guardia de Credenciales**, una característica exclusiva de **Windows 10 (ediciones Enterprise y Education)**, mejora la seguridad de las credenciales de la máquina utilizando **Modo Seguro Virtual (VSM)** y **Seguridad Basada en Virtualización (VBS)**. Aprovecha las extensiones de virtualización de la CPU para aislar procesos clave dentro de un espacio de memoria protegido, lejos del alcance del sistema operativo principal. Esta aislamiento garantiza que ni siquiera el kernel pueda acceder a la memoria en VSM, protegiendo efectivamente las credenciales de ataques como **pass-the-hash**. La **Autoridad de Seguridad Local (LSA)** opera dentro de este entorno seguro como un trustlet, mientras que el proceso **LSASS** en el sistema operativo principal actúa simplemente como un comunicador con la LSA de VSM.

Por defecto, **Guardia de Credenciales** no está activa y requiere activación manual dentro de una organización. Es fundamental para mejorar la seguridad contra herramientas como **Mimikatz**, que se ven obstaculizadas en su capacidad para extraer credenciales. Sin embargo, las vulnerabilidades aún pueden ser explotadas a través de la adición de **Proveedores de Soporte de Seguridad (SSP)** personalizados para capturar credenciales en texto claro durante intentos de inicio de sesión.

Para verificar el estado de activación de **Guardia de Credenciales**, se puede inspeccionar la clave del registro **_LsaCfgFlags_** bajo **_HKLM\System\CurrentControlSet\Control\LSA_**. Un valor de "**1**" indica activación con **bloqueo UEFI**, "**2**" sin bloqueo, y "**0**" indica que no está habilitado. Esta verificación en el registro, aunque es un indicador sólido, no es el único paso para habilitar Guardia de Credenciales. Orientación detallada y un script de PowerShell para habilitar esta característica están disponibles en línea.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para obtener una comprensión completa e instrucciones sobre cómo habilitar **Credential Guard** en Windows 10 y su activación automática en sistemas compatibles de **Windows 11 Enterprise y Education (versión 22H2)**, visita la [documentación de Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Para obtener más detalles sobre la implementación de SSP personalizados para la captura de credenciales, consulta [esta guía](../active-directory-methodology/custom-ssp.md).


## Modo RestrictedAdmin de RDP

**Windows 8.1 y Windows Server 2012 R2** introdujeron varias características de seguridad nuevas, incluido el **_modo Restricted Admin para RDP_**. Este modo fue diseñado para mejorar la seguridad al mitigar los riesgos asociados con los ataques de **[pasar el hash](https://blog.ahasayen.com/pass-the-hash/)**.

Tradicionalmente, al conectarse a una computadora remota a través de RDP, sus credenciales se almacenan en la máquina de destino. Esto plantea un riesgo de seguridad significativo, especialmente al usar cuentas con privilegios elevados. Sin embargo, con la introducción del **_modo Restricted Admin_**, este riesgo se reduce sustancialmente.

Al iniciar una conexión RDP utilizando el comando **mstsc.exe /RestrictedAdmin**, la autenticación en la computadora remota se realiza sin almacenar sus credenciales en ella. Este enfoque garantiza que, en caso de una infección de malware o si un usuario malintencionado obtiene acceso al servidor remoto, sus credenciales no se vean comprometidas, ya que no se almacenan en el servidor.

Es importante tener en cuenta que en el **modo Restricted Admin**, los intentos de acceder a recursos de red desde la sesión RDP no utilizarán sus credenciales personales; en su lugar, se utilizará la **identidad de la máquina**.

Esta característica marca un avance significativo en la seguridad de las conexiones de escritorio remoto y en la protección de la información confidencial para evitar su exposición en caso de una violación de seguridad.

![](../../.gitbook/assets/ram.png)

Para obtener más información detallada, visita [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Credenciales en Caché

Windows asegura las **credenciales de dominio** a través de la **Autoridad de Seguridad Local (LSA)**, admitiendo procesos de inicio de sesión con protocolos de seguridad como **Kerberos** y **NTLM**. Una característica clave de Windows es su capacidad para almacenar en caché los **últimos diez inicios de sesión de dominio** para garantizar que los usuarios aún puedan acceder a sus computadoras incluso si el **controlador de dominio está fuera de línea**—una ventaja para los usuarios de portátiles que a menudo están lejos de la red de su empresa.

El número de inicios de sesión en caché es ajustable a través de una **clave de registro específica o una directiva de grupo**. Para ver o cambiar esta configuración, se utiliza el siguiente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
El acceso a estas credenciales en caché está estrictamente controlado, con solo la cuenta **SYSTEM** teniendo los permisos necesarios para verlas. Los administradores que necesiten acceder a esta información deben hacerlo con privilegios de usuario SYSTEM. Las credenciales se almacenan en: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** se puede utilizar para extraer estas credenciales en caché usando el comando `lsadump::cache`.

Para más detalles, la [fuente](http://juggernaut.wikidot.com/cached-credentials) original proporciona información detallada.

## Usuarios Protegidos

La membresía en el grupo **Protected Users** introduce varias mejoras de seguridad para los usuarios, garantizando niveles más altos de protección contra el robo y mal uso de credenciales:

- **Delegación de Credenciales (CredSSP)**: Incluso si la configuración de directiva de grupo para **Permitir la delegación de credenciales predeterminadas** está habilitada, las credenciales en texto plano de los Usuarios Protegidos no se almacenarán en caché.
- **Windows Digest**: A partir de **Windows 8.1 y Windows Server 2012 R2**, el sistema no almacenará en caché las credenciales en texto plano de los Usuarios Protegidos, independientemente del estado de Windows Digest.
- **NTLM**: El sistema no almacenará en caché las credenciales en texto plano de los Usuarios Protegidos ni las funciones unidireccionales NT (NTOWF).
- **Kerberos**: Para los Usuarios Protegidos, la autenticación Kerberos no generará claves **DES** o **RC4**, ni almacenará en caché las credenciales en texto plano o claves a largo plazo más allá de la adquisición inicial del Ticket-Granting Ticket (TGT).
- **Inicio de Sesión sin Conexión**: Los Usuarios Protegidos no tendrán un verificador en caché creado al iniciar sesión o desbloquear, lo que significa que el inicio de sesión sin conexión no es compatible para estas cuentas.

Estas protecciones se activan en el momento en que un usuario, que es miembro del grupo **Protected Users**, inicia sesión en el dispositivo. Esto garantiza que se implementen medidas de seguridad críticas para protegerse contra varios métodos de compromiso de credenciales.

Para obtener información más detallada, consulte la [documentación](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) oficial.

**Tabla de** [**la documentación**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |
