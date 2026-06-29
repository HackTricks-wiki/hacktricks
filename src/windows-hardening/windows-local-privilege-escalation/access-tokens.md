# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Cada **usuario que ha iniciado sesión** en el sistema **tiene un access token con información de seguridad** para esa sesión de inicio de sesión. El sistema crea un access token cuando el usuario inicia sesión. **Cada proceso ejecutado** en nombre del usuario **tiene una copia del access token**. El token identifica al usuario, los grupos del usuario y los privilegios del usuario. Un token también contiene un logon SID (Security Identifier) que identifica la sesión de inicio de sesión actual.

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
o usando _Process Explorer_ de Sysinternals (selecciona el proceso y accede a la pestaña "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

Cuando un administrador local inicia sesión, **se crean dos access tokens**: uno con derechos de administrador y otro con derechos normales. **Por defecto**, cuando este usuario ejecuta un proceso, se usa el de **derechos** regulares (no administrador). Cuando este usuario intenta **ejecutar** algo **como administrador** ("Run as Administrator", por ejemplo), se usará el **UAC** para pedir permiso.\
Si quieres [**aprender más sobre el UAC, lee esta página**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

En la práctica, esto significa que un **shell de admin no elevado normalmente se ejecuta con un filtered token**. Por eso `whoami /groups` a menudo muestra **`BUILTIN\Administrators` como `Deny only`** hasta que el proceso se eleva. Internamente, Windows mantiene un **linked elevated token** (`TokenLinkedToken`) y rastrea el estado con campos como `TokenElevationType`.

### Credentials user impersonation

Si tienes **credenciales válidas de cualquier otro usuario**, puedes **crear** una **nueva sesión de logon** con esas credenciales :
```
runas /user:domain\username cmd.exe
```
El **access token** también tiene una **reference** de las sesiones de inicio de sesión dentro de **LSASS**, esto es útil si el proceso necesita acceder a algunos objetos de la red.\
Puedes iniciar un proceso que **uses different credentials for accessing network services** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Esto es útil si tienes credenciales útiles para acceder a objetos en la red, pero esas credenciales no son válidas dentro del host actual, ya que solo se van a usar en la red (en el host actual se usarán los privilegios de tu usuario actual).

#### `runas /netonly` details

`runas /netonly` (y helpers de C2 como `make_token`) crea un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Esto es muy útil de entender durante lateral movement porque:

- **Localmente**, el nuevo proceso conserva la **misma identidad local**, grupos, nivel de integridad y la mayoría de las mismas decisiones de acceso que el token actual.
- **Remotamente**, la autenticación saliente puede usar las **credenciales proporcionadas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Por lo tanto, `whoami` puede seguir mostrando el **usuario local original** mientras el acceso a la red ocurre como la **cuenta alternativa**.

Esta es una gran opción cuando las credenciales son válidas en el dominio o en otro host, pero el usuario **no puede o no debe iniciar sesión localmente** en la máquina actual.

### Types of tokens

Hay dos tipos de tokens disponibles:

- **Primary Token**: Sirve como representación de las credenciales de seguridad de un proceso. La creación y asociación de primary tokens con procesos son acciones que requieren privilegios elevados, lo que enfatiza el principio de separación de privilegios. Normalmente, un servicio de autenticación es responsable de la creación del token, mientras que un servicio de logon gestiona su asociación con la shell del sistema operativo del usuario. Cabe señalar que los procesos heredan el primary token de su proceso padre al crearse.
- **Impersonation Token**: Permite a una aplicación servidor adoptar temporalmente la identidad del cliente para acceder a objetos seguros. Este mecanismo se divide en cuatro niveles de operación:
- **Anonymous**: Concede acceso al servidor de forma similar a la de un usuario no identificado.
- **Identification**: Permite al servidor verificar la identidad del cliente sin utilizarla para el acceso a objetos.
- **Impersonation**: Permite al servidor operar bajo la identidad del cliente.
- **Delegation**: Similar a Impersonation, pero incluye la capacidad de extender esta asunción de identidad a sistemas remotos con los que interactúa el servidor, asegurando la preservación de credenciales.

#### Impersonate Tokens

Usando el módulo _**incognito**_ de metasploit, si tienes suficientes privilegios puedes fácilmente **listar** e **impersonar** otros **tokens**. Esto podría ser útil para realizar **acciones como si fueras el otro usuario**. También podrías **escalar privilegios** con esta técnica.

Algunas notas prácticas que son fáciles de olvidar أثناء operar:

- **`CreateProcessWithTokenW`** requiere **`SeImpersonatePrivilege`** en el llamador y el nuevo proceso se ejecutará en la **sesión del llamador**.
- **`CreateProcessAsUserW`** es el fallback habitual cuando `CreateProcessWithTokenW` falla con `1314`, o cuando necesitas lanzar en la **sesión referenciada por el token**.
- Si un token proviene de **`LogonUser(LOGON32_LOGON_NETWORK)`**, normalmente es un **impersonation token**, así que necesitas **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de intentar crear un proceso con él.
- No todos los impersonation token son igual de útiles: **`SecurityIdentification`** te permite inspeccionar al usuario pero **no actuar como él**. Si un primitive de coercion o un cliente pipe/RPC solo te da un token de nivel identification, comprueba **`TokenImpersonationLevel`** y cambia a un primitive que devuelva **`SecurityImpersonation`** o mejor.

#### Token theft without touching LSASS

Si ya tienes un contexto de **servicio** o **SYSTEM** y un **usuario privilegiado está conectado**, robar o duplicar el token de ese usuario suele ser más discreto que volcar **LSASS**. En muchas intrusiones reales esto basta para:

- ejecutar acciones locales como ese usuario
- acceder a recursos remotos como ese usuario
- realizar operaciones de AD sin extraer primero credenciales reutilizables

Para ejemplos de **session/user token hijacking** desde un contexto privilegiado, revisa [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Recuerda que APIs como **`WTSQueryUserToken`** están pensadas para **servicios altamente confiables** y normalmente requieren **`LocalSystem` + `SeTcbPrivilege`**, así que son principalmente útiles una vez que ya controlas un contexto a nivel de servicio. Para formas específicas de privilegios de obtener primero **SYSTEM**, revisa las páginas de abajo.

### Token Privileges

Aprende qué **token privileges pueden abusarse para escalar privilegios:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Echa un vistazo a [**todos los posibles token privileges y algunas definiciones en esta página externa**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
