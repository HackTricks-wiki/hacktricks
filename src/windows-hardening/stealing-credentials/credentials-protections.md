# Protecciones de Credenciales de Windows

## Protecciones de Credenciales

{{#include ../../banners/hacktricks-training.md}}

## WDigest

El protocolo [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introducido con Windows XP, está diseñado para la autenticación a través del Protocolo HTTP y está **habilitado por defecto en Windows XP hasta Windows 8.0 y Windows Server 2003 hasta Windows Server 2012**. Esta configuración predeterminada resulta en **almacenamiento de contraseñas en texto plano en LSASS** (Servicio de Subsistema de Autoridad de Seguridad Local). Un atacante puede usar Mimikatz para **extraer estas credenciales** ejecutando:
```bash
sekurlsa::wdigest
```
Para **activar o desactivar esta función**, las claves de registro _**UseLogonCredential**_ y _**Negotiate**_ dentro de _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ deben estar configuradas en "1". Si estas claves están **ausentes o configuradas en "0"**, WDigest está **deshabilitado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protección de LSA

A partir de **Windows 8.1**, Microsoft mejoró la seguridad de LSA para **bloquear lecturas de memoria no autorizadas o inyecciones de código por procesos no confiables**. Esta mejora obstaculiza el funcionamiento típico de comandos como `mimikatz.exe sekurlsa:logonpasswords`. Para **habilitar esta protección mejorada**, el valor _**RunAsPPL**_ en _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ debe ajustarse a 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Es posible eludir esta protección utilizando el controlador de Mimikatz mimidrv.sys:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, una característica exclusiva de **Windows 10 (ediciones Enterprise y Education)**, mejora la seguridad de las credenciales de la máquina utilizando **Virtual Secure Mode (VSM)** y **Virtualization Based Security (VBS)**. Aprovecha las extensiones de virtualización de la CPU para aislar procesos clave dentro de un espacio de memoria protegido, lejos del alcance del sistema operativo principal. Este aislamiento asegura que incluso el kernel no pueda acceder a la memoria en VSM, protegiendo efectivamente las credenciales de ataques como **pass-the-hash**. La **Local Security Authority (LSA)** opera dentro de este entorno seguro como un trustlet, mientras que el proceso **LSASS** en el sistema operativo principal actúa simplemente como un comunicador con la LSA de VSM.

Por defecto, **Credential Guard** no está activo y requiere activación manual dentro de una organización. Es fundamental para mejorar la seguridad contra herramientas como **Mimikatz**, que se ven obstaculizadas en su capacidad para extraer credenciales. Sin embargo, las vulnerabilidades aún pueden ser explotadas mediante la adición de **Security Support Providers (SSP)** personalizados para capturar credenciales en texto claro durante los intentos de inicio de sesión.

Para verificar el estado de activación de **Credential Guard**, se puede inspeccionar la clave del registro _**LsaCfgFlags**_ bajo _**HKLM\System\CurrentControlSet\Control\LSA**_. Un valor de "**1**" indica activación con **UEFI lock**, "**2**" sin bloqueo, y "**0**" denota que no está habilitado. Esta verificación del registro, aunque es un fuerte indicador, no es el único paso para habilitar Credential Guard. Se dispone de orientación detallada y un script de PowerShell para habilitar esta característica en línea.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para una comprensión completa e instrucciones sobre cómo habilitar **Credential Guard** en Windows 10 y su activación automática en sistemas compatibles de **Windows 11 Enterprise y Education (versión 22H2)**, visita [la documentación de Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Más detalles sobre la implementación de SSPs personalizados para la captura de credenciales se proporcionan en [esta guía](../active-directory-methodology/custom-ssp.md).

## Modo RestrictedAdmin de RDP

**Windows 8.1 y Windows Server 2012 R2** introdujeron varias nuevas características de seguridad, incluido el _**modo Restricted Admin para RDP**_. Este modo fue diseñado para mejorar la seguridad al mitigar los riesgos asociados con [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) ataques.

Tradicionalmente, al conectarse a una computadora remota a través de RDP, sus credenciales se almacenan en la máquina objetivo. Esto representa un riesgo de seguridad significativo, especialmente al usar cuentas con privilegios elevados. Sin embargo, con la introducción del _**modo Restricted Admin**_, este riesgo se reduce sustancialmente.

Al iniciar una conexión RDP utilizando el comando **mstsc.exe /RestrictedAdmin**, la autenticación en la computadora remota se realiza sin almacenar sus credenciales en ella. Este enfoque asegura que, en caso de una infección de malware o si un usuario malicioso obtiene acceso al servidor remoto, sus credenciales no se vean comprometidas, ya que no están almacenadas en el servidor.

Es importante tener en cuenta que en **modo Restricted Admin**, los intentos de acceder a recursos de red desde la sesión RDP no utilizarán sus credenciales personales; en su lugar, se utiliza la **identidad de la máquina**.

Esta característica marca un avance significativo en la seguridad de las conexiones de escritorio remoto y en la protección de información sensible de ser expuesta en caso de una violación de seguridad.

![](../../images/RAM.png)

Para obtener más información detallada, visita [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciales en caché

Windows asegura **credenciales de dominio** a través de la **Autoridad de Seguridad Local (LSA)**, apoyando procesos de inicio de sesión con protocolos de seguridad como **Kerberos** y **NTLM**. Una característica clave de Windows es su capacidad para almacenar en caché los **últimos diez inicios de sesión de dominio** para garantizar que los usuarios aún puedan acceder a sus computadoras incluso si el **controlador de dominio está fuera de línea**—una ventaja para los usuarios de laptops que a menudo están fuera de la red de su empresa.

El número de inicios de sesión en caché es ajustable a través de una **clave de registro o política de grupo** específica. Para ver o cambiar esta configuración, se utiliza el siguiente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
El acceso a estas credenciales en caché está estrictamente controlado, con solo la cuenta **SYSTEM** teniendo los permisos necesarios para verlas. Los administradores que necesiten acceder a esta información deben hacerlo con privilegios de usuario SYSTEM. Las credenciales se almacenan en: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** se puede emplear para extraer estas credenciales en caché utilizando el comando `lsadump::cache`.

Para más detalles, la [fuente](http://juggernaut.wikidot.com/cached-credentials) original proporciona información completa.

## Usuarios Protegidos

La membresía en el **grupo de Usuarios Protegidos** introduce varias mejoras de seguridad para los usuarios, asegurando niveles más altos de protección contra el robo y el uso indebido de credenciales:

- **Delegación de Credenciales (CredSSP)**: Incluso si la configuración de Directiva de Grupo para **Permitir delegar credenciales predeterminadas** está habilitada, las credenciales en texto plano de los Usuarios Protegidos no se almacenarán en caché.
- **Windows Digest**: A partir de **Windows 8.1 y Windows Server 2012 R2**, el sistema no almacenará en caché las credenciales en texto plano de los Usuarios Protegidos, independientemente del estado de Windows Digest.
- **NTLM**: El sistema no almacenará en caché las credenciales en texto plano de los Usuarios Protegidos ni funciones unidireccionales NT (NTOWF).
- **Kerberos**: Para los Usuarios Protegidos, la autenticación Kerberos no generará **claves DES** o **RC4**, ni almacenará en caché credenciales en texto plano o claves a largo plazo más allá de la adquisición inicial del Ticket-Granting Ticket (TGT).
- **Inicio de Sesión Offline**: Los Usuarios Protegidos no tendrán un verificador en caché creado al iniciar sesión o desbloquear, lo que significa que el inicio de sesión offline no es compatible con estas cuentas.

Estas protecciones se activan en el momento en que un usuario, que es miembro del **grupo de Usuarios Protegidos**, inicia sesión en el dispositivo. Esto asegura que se implementen medidas de seguridad críticas para proteger contra varios métodos de compromiso de credenciales.

Para obtener información más detallada, consulte la [documentación](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) oficial.

**Tabla de** [**los docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

{{#include ../../banners/hacktricks-training.md}}
