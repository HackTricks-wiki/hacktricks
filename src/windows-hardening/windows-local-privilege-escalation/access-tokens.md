# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Cada **usuario conectado** al sistema **tiene un token de acceso con información de seguridad** para esa sesión de inicio. El sistema crea un token de acceso cuando el usuario inicia sesión. **Cada proceso ejecutado** en nombre del usuario **tiene una copia del token de acceso**. El token identifica al usuario, los grupos del usuario y los privilegios del usuario. Un token también contiene un SID de inicio de sesión (Identificador de Seguridad) que identifica la sesión de inicio actual.

Puedes ver esta información ejecutando `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
o usando _Process Explorer_ de Sysinternals (seleccionar proceso y acceder a la pestaña "Seguridad"):

![](<../../images/image (772).png>)

### Administrador local

Cuando un administrador local inicia sesión, **se crean dos tokens de acceso**: uno con derechos de administrador y otro con derechos normales. **Por defecto**, cuando este usuario ejecuta un proceso, se utiliza el que tiene **derechos regulares** (no de administrador). Cuando este usuario intenta **ejecutar** algo **como administrador** ("Ejecutar como administrador", por ejemplo), se utilizará el **UAC** para pedir permiso.\
Si quieres [**aprender más sobre el UAC, lee esta página**](../authentication-credentials-uac-and-efs/#uac)**.**

### Suplantación de credenciales de usuario

Si tienes **credenciales válidas de cualquier otro usuario**, puedes **crear** una **nueva sesión de inicio de sesión** con esas credenciales:
```
runas /user:domain\username cmd.exe
```
El **access token** también tiene una **referencia** de las sesiones de inicio de sesión dentro del **LSASS**, esto es útil si el proceso necesita acceder a algunos objetos de la red.\
Puedes lanzar un proceso que **utiliza diferentes credenciales para acceder a servicios de red** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Esto es útil si tienes credenciales útiles para acceder a objetos en la red, pero esas credenciales no son válidas dentro del host actual, ya que solo se utilizarán en la red (en el host actual se utilizarán los privilegios de usuario actuales).

### Tipos de tokens

Hay dos tipos de tokens disponibles:

- **Token Primario**: Sirve como representación de las credenciales de seguridad de un proceso. La creación y asociación de tokens primarios con procesos son acciones que requieren privilegios elevados, enfatizando el principio de separación de privilegios. Típicamente, un servicio de autenticación es responsable de la creación del token, mientras que un servicio de inicio de sesión maneja su asociación con el shell del sistema operativo del usuario. Vale la pena señalar que los procesos heredan el token primario de su proceso padre al ser creados.
- **Token de Suplantación**: Permite a una aplicación de servidor adoptar temporalmente la identidad del cliente para acceder a objetos seguros. Este mecanismo se estratifica en cuatro niveles de operación:
- **Anónimo**: Otorga acceso al servidor similar al de un usuario no identificado.
- **Identificación**: Permite al servidor verificar la identidad del cliente sin utilizarla para el acceso a objetos.
- **Suplantación**: Permite al servidor operar bajo la identidad del cliente.
- **Delegación**: Similar a la Suplantación, pero incluye la capacidad de extender esta asunción de identidad a sistemas remotos con los que el servidor interactúa, asegurando la preservación de credenciales.

#### Tokens de Suplantación

Usando el módulo _**incognito**_ de metasploit, si tienes suficientes privilegios, puedes fácilmente **listar** y **suplantar** otros **tokens**. Esto podría ser útil para realizar **acciones como si fueras el otro usuario**. También podrías **escalar privilegios** con esta técnica.

### Privilegios de Token

Aprende qué **privilegios de token pueden ser abusados para escalar privilegios:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Echa un vistazo a [**todos los posibles privilegios de token y algunas definiciones en esta página externa**](https://github.com/gtworek/Priv2Admin).

## Referencias

Aprende más sobre tokens en estos tutoriales: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) y [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
