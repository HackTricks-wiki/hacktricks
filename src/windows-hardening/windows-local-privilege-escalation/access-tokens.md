# Tokens de acceso

{{#include ../../banners/hacktricks-training.md}}

## Tokens de acceso

Cada **usuario conectado** al sistema **tiene un token de acceso con información de seguridad** para esa sesión de inicio de sesión. El sistema crea un token de acceso cuando el usuario inicia sesión. **Cada proceso ejecutado** en nombre del usuario **tiene una copia del token de acceso**. El token identifica al usuario, los grupos del usuario y los privilegios del usuario. Un token también contiene un SID de inicio de sesión (identificador de seguridad) que identifica la sesión de inicio de sesión actual.

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

![Access Tokens - Access Tokens: o usando Process Explorer de Sysinternals (selecciona el proceso y accede a la pestaña "Security")](<../../images/image (772).png>)

### Administrador local

Cuando un administrador local inicia sesión, **se crean dos tokens de acceso**: uno con derechos de administrador y otro con derechos normales. **De forma predeterminada**, cuando este usuario ejecuta un proceso, se utiliza el que tiene **derechos** **normales** (no administrativos). Cuando este usuario intenta **ejecutar** algo **como administrador** (por ejemplo, "Run as Administrator"), se utilizará **UAC** para solicitar permiso.\
Si quieres [**aprender más sobre UAC, lee esta página**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

En la práctica, esto significa que un **shell de administrador no elevado normalmente se ejecuta con un token filtrado**. Por eso `whoami /groups` suele mostrar **`BUILTIN\Administrators` como `Deny only`** hasta que el proceso se eleva. Internamente, Windows mantiene un **token elevado vinculado** (`TokenLinkedToken`) y realiza un seguimiento del estado mediante campos como `TokenElevationType`.

### Suplantación de usuario mediante credenciales

Si tienes **credenciales válidas de cualquier otro usuario**, puedes **crear** una **nueva sesión de inicio de sesión** con esas credenciales:
```
runas /user:domain\username cmd.exe
```
El **access token** también tiene una **referencia** a las sesiones de inicio de sesión dentro de **LSASS**, lo que resulta útil si el proceso necesita acceder a algunos objetos de la red.\
Puedes iniciar un proceso que **use credenciales diferentes para acceder a servicios de red** mediante:
```
runas /user:domain\username /netonly cmd.exe
```
Esto es útil si tienes credenciales válidas para acceder a objetos de la red, pero esas credenciales no son válidas dentro del host actual, ya que solo se utilizarán en la red (en el host actual se utilizarán los privilegios de tu usuario actual).

#### Detalles de `runas /netonly`

`runas /netonly` (y helpers de C2 como `make_token`) crea un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Esto es muy útil para comprender el movimiento lateral porque:<sup>[[3]](#references)</sup>

- **Localmente**, el nuevo proceso conserva la **misma identidad local**, grupos, nivel de integridad y la mayoría de las mismas decisiones de acceso que el token actual.
- **Remotamente**, la autenticación saliente puede utilizar las **credenciales proporcionadas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Por lo tanto, `whoami` puede seguir mostrando el **usuario local original**, mientras que el acceso a la red se realiza como la **cuenta alternativa**.

Esta es una excelente opción cuando las credenciales son válidas en el dominio o en otro host, pero el usuario **no puede o no debería iniciar sesión localmente** en la máquina actual.

### Tipos de tokens

Hay dos tipos de tokens disponibles:

- **Primary Token**: Sirve como representación de las credenciales de seguridad de un proceso. La creación y asociación de Primary Tokens con procesos son acciones que requieren privilegios elevados, lo que enfatiza el principio de separación de privilegios. Normalmente, un servicio de autenticación se encarga de crear el token, mientras que un servicio de inicio de sesión gestiona su asociación con el shell del sistema operativo del usuario. Cabe señalar que, al crearse, los procesos heredan el Primary Token de su proceso principal.
- **Impersonation Token**: Permite que una aplicación de servidor adopte temporalmente la identidad del cliente para acceder a objetos protegidos. Este mecanismo se divide en cuatro niveles de operación:
- **Anonymous**: Concede al servidor un acceso similar al de un usuario no identificado.
- **Identification**: Permite al servidor verificar la identidad del cliente sin utilizarla para acceder a objetos.
- **Impersonation**: Permite al servidor operar bajo la identidad del cliente.
- **Delegation**: Es similar a Impersonation, pero también permite extender esta suposición de identidad a los sistemas remotos con los que interactúa el servidor, garantizando la conservación de las credenciales.

#### Impersonate Tokens

Mediante el módulo _**incognito**_ de metasploit, si tienes suficientes privilegios, puedes **listar** e **impersonar** fácilmente otros **tokens**. Esto puede ser útil para realizar **acciones como si fueras el otro usuario**. También podrías **escalar privilegios** con esta técnica.

Algunas notas prácticas que son fáciles de olvidar durante la operación:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** requiere **`SeImpersonatePrivilege`** en el proceso que realiza la llamada, y el nuevo proceso se ejecutará en la **sesión del proceso que realiza la llamada**.
- **`CreateProcessAsUserW`** es el fallback habitual cuando `CreateProcessWithTokenW` falla con `1314`, o cuando necesitas iniciar el proceso en la **sesión referenciada por el token**.
- Si un token proviene de **`LogonUser(LOGON32_LOGON_NETWORK)`**, normalmente es un **impersonation token**, por lo que necesitas **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de intentar crear un proceso con él.
- No todos los impersonation tokens son igual de útiles: **`SecurityIdentification`** permite inspeccionar al usuario, pero **no actuar como él**. Si un primitive de coerción o un cliente de pipe/RPC solo te proporciona un token de nivel identification, comprueba **`TokenImpersonationLevel`** y cambia a un primitive que proporcione **`SecurityImpersonation`** o un nivel superior.

#### Token theft without touching LSASS

Si ya tienes un contexto de **service** o **SYSTEM** y hay un **usuario privilegiado conectado**, robar o duplicar el token de ese usuario suele ser más silencioso que volcar **LSASS**. En muchas intrusiones reales, esto basta para:<sup>[[2]](#references)</sup>

- ejecutar acciones locales como ese usuario
- acceder a recursos remotos como ese usuario
- realizar operaciones de AD sin extraer primero credenciales reutilizables

Para ver ejemplos de **session/user token hijacking** desde un contexto privilegiado, consulta [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Recuerda que APIs como **`WTSQueryUserToken`** están destinadas a **servicios altamente confiables** y normalmente requieren **`LocalSystem` + `SeTcbPrivilege`**, por lo que son principalmente útiles cuando ya controlas un contexto de nivel service. Para consultar métodos específicos según los privilegios para obtener primero **SYSTEM**, revisa las páginas siguientes.

### Token Privileges

Aprende qué **token privileges pueden abusarse para escalar privilegios:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Consulta [**todos los token privileges posibles y algunas definiciones en esta página externa**](https://github.com/gtworek/Priv2Admin).

## Referencias

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
