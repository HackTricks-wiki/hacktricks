# Tokens de acceso

{{#include ../../banners/hacktricks-training.md}}

## Tokens de acceso

Cada proceso tiene un **token de acceso principal** que define su contexto de seguridad. Un subproceso normalmente usa ese token, pero también puede tener temporalmente un **token de suplantación**. Los tokens contienen el SID del usuario, los SID de grupo, privilegios, información de integridad y un SID de inicio de sesión para la sesión de inicio de sesión. Por lo general, los procesos heredan una referencia al token principal del proceso padre; no reciben una copia independiente de su contenido.<sup>[[4]](#references)</sup>

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

Cuando **UAC Admin Approval Mode** se aplica a un administrador, el inicio de sesión interactivo crea un token de administrador completo y un token filtrado. Explorer y los procesos secundarios normales usan el token filtrado de forma predeterminada. Una solicitud de elevación, como **Run as administrator**, pide a UAC que inicie el programa con el token completo. El comportamiento exacto varía según se trate de la cuenta de administrador integrada y según esté deshabilitado Admin Approval Mode.<sup>[[5]](#references)</sup>

Consulta la [**página de UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md), dedicada a las técnicas de bypass y los detalles de las políticas.

En la práctica, esto significa que un **shell de administrador sin elevación suele ejecutarse con un token filtrado**. Por eso, `whoami /groups` suele mostrar **`BUILTIN\Administrators` como `Deny only`** hasta que se eleva el proceso. Internamente, Windows mantiene un **token elevado vinculado** (`TokenLinkedToken`) y registra el estado con campos como `TokenElevationType`.

### Suplantación de usuario con credenciales

Si tienes **credenciales válidas de cualquier otro usuario**, puedes **crear** una **nueva sesión de inicio de sesión** con esas credenciales:

```
runas /user:domain\username cmd.exe
```

El **token de acceso** también contiene una **referencia** a las sesiones de inicio de sesión dentro de **LSASS**; esto es útil si el proceso necesita acceder a algunos objetos de la red.\
Puedes iniciar un proceso que **use credenciales diferentes para acceder a servicios de red** usando:

```
runas /user:domain\username /netonly cmd.exe
```

Esto es útil si tienes credenciales válidas para acceder a objetos de la red, pero esas credenciales no son válidas en el host actual, ya que solo se usarán en la red (en el host actual se usarán los privilegios del usuario actual).

#### Detalles de `runas /netonly`

`runas /netonly` (y los helpers de C2, como `make_token`) crea un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Es muy útil entenderlo durante el movimiento lateral porque:<sup>[[3]](#references)</sup>

- **Localmente**, el nuevo proceso conserva la **misma identidad local**, los grupos, el nivel de integridad y la mayoría de las mismas decisiones de acceso que el token actual.
- **Remotamente**, la autenticación saliente puede usar las **credenciales proporcionadas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Por lo tanto, `whoami` puede seguir mostrando el **usuario local original** mientras que el acceso a la red se realiza como la **cuenta alternativa**.

Esta es una excelente opción cuando las credenciales son válidas en el dominio o en otro host, pero el usuario **no puede o no debería iniciar sesión localmente** en la máquina actual.

### Tipos de tokens

Hay dos tipos de tokens disponibles:<sup>[[4]](#references)[[6]](#references)</sup>

- **Token primario**: Representa el contexto de seguridad de un proceso. Normalmente, un proceso hijo hereda el token primario de su proceso padre, mientras que las API de creación de procesos con token explícito imponen sus propios requisitos de acceso al token y de privilegios del llamador.
- **Token de suplantación**: Permite que un subproceso del servidor use temporalmente el contexto de seguridad de un cliente para realizar comprobaciones de acceso. Tiene cuatro niveles:
  - **Anónimo**: Otorga al servidor un acceso similar al de un usuario no identificado.
  - **Identificación**: Permite al servidor verificar la identidad del cliente sin usarla para acceder a objetos.
  - **Suplantación**: Permite al servidor operar con la identidad del cliente.
  - **Delegación**: Permite al servidor suplantar al cliente en sistemas remotos cuando el mecanismo de autenticación y la configuración de la cuenta admiten la delegación.

#### Clasifica un token capturado antes de usarlo

No selecciones un token solo por el nombre de usuario. Una misma cuenta puede tener varios tokens con distintas sesiones de inicio de sesión, SID de servicio, privilegios, niveles de integridad, restricciones y credenciales de red.<sup>[[9]](#references)</sup> Consulta al menos **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** y **`TokenStatistics.AuthenticationId`** con `GetTokenInformation`.<sup>[[7]](#references)</sup>

Un token restringido puede contener SID de solo denegación, privilegios eliminados y SID restrictivos. Cuando existen SID restrictivos, Windows realiza una comprobación de acceso con los SID habilitados y otra con los SID restrictivos; **ambas comprobaciones deben permitir el acceso**. Por lo tanto, que aparezca un SID de usuario atractivo o un grupo habilitado no demuestra por sí solo que el token pueda acceder al objeto de destino.<sup>[[8]](#references)</sup>

Usa este flujo de decisión para los requisitos documentados de tokens y creación de procesos:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Un **token primario** necesita un identificador con `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` antes de poder pasarse a `CreateProcessWithTokenW` o `CreateProcessAsUserW`.
2. Convierte un **token de suplantación** con `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Los tokens de nivel Identification pueden exponer datos de identidad, pero no pueden realizar comprobaciones de acceso como ese cliente.
3. `CreateProcessWithTokenW` necesita `SeImpersonatePrivilege` e inicia el proceso hijo en la sesión del llamador. En cambio, `CreateProcessAsUserW` usa la sesión del token, pero normalmente necesita `SeIncreaseQuotaPrivilege` y puede necesitar `SeAssignPrimaryTokenPrivilege`. Si hay credenciales disponibles y faltan estos privilegios, la alternativa documentada es `CreateProcessWithLogonW`.

#### Busca identificadores de token, no solo propietarios de procesos

Abrir el token primario de cada proceso puede hacer que se pasen por alto **tokens de suplantación conservados como identificadores normales** dentro de servicios y procesos broker. Un flujo de trabajo reutilizable con tablas de identificadores consiste en enumerar los identificadores del sistema, filtrar los objetos de tipo token, abrir cada proceso propietario con `PROCESS_DUP_HANDLE`, duplicar el identificador candidato en el proceso actual y, después, consultar los campos anteriores. Confirma que el identificador duplicado incluya `TOKEN_QUERY` y `TOKEN_DUPLICATE`; encontrar un identificador de token no significa que se pueda duplicar para obtener un token primario utilizable. Los procesos protegidos y las DACL de procesos aún pueden impedir el acceso al identificador del proceso propietario.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatiza tanto la enumeración de tokens primarios de procesos como la de identificadores de tokens conservados. `list_token` conserva un candidato preferido por nombre de usuario, mientras que `list_all_token` muestra todos los candidatos. Un PID limita la enumeración a un único proceso propietario.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Para la inspección manual y la comprobación de acceso, **TokenUniverse** puede abrir tokens de procesos/hilos, buscar handles de tokens existentes, inspeccionar restricciones y sesiones de inicio de sesión, duplicar tokens y probar varios métodos de creación de procesos.<sup>[[13]](#references)</sup> Para conocer el primitive subyacente de handles entre procesos, consulta:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Suplantar tokens

Si tienes suficientes privilegios, puedes usar el módulo _**incognito**_ de metasploit para **listar** y **suplantar** fácilmente otros **tokens**. Esto puede ser útil para realizar **acciones como si fueras el otro usuario**. También podrías **escalar privilegios** con esta técnica.

Algunas notas prácticas que es fácil olvidar durante la operación:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** requiere **`SeImpersonatePrivilege`** en el proceso llamador, y el nuevo proceso se ejecutará en la **sesión del proceso llamador**.
- **`CreateProcessAsUserW`** es una alternativa posible cuando `CreateProcessWithTokenW` falla con `1314`, solo si el proceso llamador cumple sus requisitos de privilegios. También es la opción correcta cuando el proceso hijo debe ejecutarse en la **sesión a la que hace referencia el token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Si un token proviene de **`LogonUser(LOGON32_LOGON_NETWORK)`**, suele ser un **token de suplantación**, por lo que necesitas **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de intentar iniciar un proceso con él.
- No todos los tokens de suplantación son igual de útiles: **`SecurityIdentification`** te permite inspeccionar al usuario, pero **no actuar como él**. Si un primitive de coerción o un cliente de pipe/RPC solo te proporciona un token de nivel de identificación, comprueba **`TokenImpersonationLevel`** y usa un primitive que proporcione **`SecurityImpersonation`** o superior.

#### Robo de tokens sin tocar LSASS

Si ya tienes un contexto de **servicio** o **SYSTEM**, y un **usuario privilegiado ha iniciado sesión**, robar o duplicar el token de ese usuario suele ser más discreto que volcar **LSASS**. En muchas intrusiones reales, esto basta para:<sup>[[2]](#references)</sup>

- ejecutar acciones locales como ese usuario
- acceder a recursos remotos como ese usuario
- realizar operaciones de AD sin extraer primero credenciales reutilizables

Para ver ejemplos de **secuestro de tokens de sesión/usuario** desde un contexto privilegiado, consulta [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Ten en cuenta que APIs como **`WTSQueryUserToken`** están pensadas para **servicios de alta confianza** y normalmente requieren **`LocalSystem` + `SeTcbPrivilege`**, por lo que son principalmente útiles cuando ya controlas un contexto de nivel de servicio. Para conocer formas de obtener primero **SYSTEM** mediante privilegios específicos, consulta las páginas siguientes.

### Privilegios de token

Aprende qué **privilegios de token pueden abusarse para escalar privilegios:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Echa un vistazo a [**todos los posibles privilegios de token y algunas definiciones en esta página externa**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Comprender y abusar de los access tokens — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusar de los tokens de Windows para comprometer Active Directory sin tocar LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Desmitificando el comando "make_token" de Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Cómo funciona User Account Control - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Niveles de suplantación - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumeración TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokens restringidos - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Función CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Función CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Función DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
