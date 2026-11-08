# Tokens de acceso

{{#include ../../banners/hacktricks-training.md}}

## Tokens de acceso

Cada proceso tiene un **token de acceso principal** que define su contexto de seguridad. Un subproceso normalmente usa ese token, pero también puede tener temporalmente un **token de suplantación**. Los tokens contienen el SID del usuario, los SID de los grupos, los privilegios, la información de integridad y un SID de inicio de sesión para la sesión de inicio de sesión. Por lo general, los procesos heredan una referencia al token principal del proceso padre; no reciben una copia independiente de su contenido.<sup>[[4]](#references)</sup>

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

o usando _Process Explorer_ de Sysinternals (selecciona el proceso y accede a la pestaña «Seguridad»):

![Tokens de acceso - Tokens de acceso: o usando Process Explorer de Sysinternals (selecciona el proceso y accede a la pestaña «Seguridad»)](<../../images/image (772).png>)

### Administrador local

Cuando se aplica **UAC Admin Approval Mode** a un administrador, el inicio de sesión interactivo crea un token de administrador completo y un token filtrado. Explorer y los procesos secundarios comunes usan el token filtrado de forma predeterminada. Una solicitud de elevación, como **Ejecutar como administrador**, pide a UAC que inicie el programa con el token completo. El comportamiento exacto varía para la cuenta de administrador integrada y cuando Admin Approval Mode está deshabilitado.<sup>[[5]](#references)</sup>

Lee la [**página de UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) dedicada para consultar técnicas de bypass y detalles de las políticas.

En la práctica, esto significa que un **shell de administrador sin elevar normalmente se ejecuta con un token filtrado**. Por eso, `whoami /groups` suele mostrar **`BUILTIN\Administrators` como `Deny only`** hasta que se eleva el proceso. Internamente, Windows mantiene un **token elevado vinculado** (`TokenLinkedToken`) y registra el estado con campos como `TokenElevationType`.

### Suplantación de usuario con credenciales

Si tienes **credenciales válidas de cualquier otro usuario**, puedes **crear** una **nueva sesión de inicio de sesión** con esas credenciales:

```
runas /user:domain\username cmd.exe
```

El **access token** también contiene una **referencia** a las sesiones de inicio de sesión dentro de **LSASS**. Esto resulta útil si el proceso necesita acceder a ciertos objetos de la red.\
Puedes iniciar un proceso que **use credenciales diferentes para acceder a servicios de red** mediante:

```
runas /user:domain\username /netonly cmd.exe
```

Esto es útil si tienes credenciales válidas para acceder a objetos de la red, pero esas credenciales no son válidas en el host actual, ya que solo se usarán en la red (en el host actual se usarán los privilegios de tu usuario actual).

#### Detalles de `runas /netonly`

`runas /netonly` (y los helpers de C2, como `make_token`) crea un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Es muy útil entenderlo durante el lateral movement porque:<sup>[[3]](#references)</sup>

- **Localmente**, el nuevo proceso conserva la **misma identidad local**, los mismos grupos, el nivel de integridad y la mayoría de las mismas decisiones de acceso que el token actual.
- **De forma remota**, la autenticación saliente puede usar las **credenciales proporcionadas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Por lo tanto, `whoami` puede seguir mostrando el **usuario local original**, mientras que el acceso a la red se realiza como la **cuenta alternativa**.

Es una gran opción cuando las credenciales son válidas en el dominio o en otro host, pero el usuario **no puede o no debería iniciar sesión localmente** en la máquina actual.

### Tipos de tokens

Hay dos tipos de tokens disponibles:<sup>[[4]](#references)[[6]](#references)</sup>

- **Token primario**: Representa el contexto de seguridad de un proceso. Un proceso hijo normalmente hereda el token primario de su proceso padre, mientras que las API de creación de procesos con token explícito imponen sus propios requisitos de acceso al token y de privilegios del llamador.
- **Token de suplantación**: Permite que un subproceso de servidor use temporalmente el contexto de seguridad de un cliente para realizar comprobaciones de acceso. Tiene cuatro niveles:
  - **Anónimo**: Otorga al servidor un acceso similar al de un usuario no identificado.
  - **Identificación**: Permite que el servidor verifique la identidad del cliente sin usarla para acceder a objetos.
  - **Suplantación**: Permite que el servidor opere con la identidad del cliente.
  - **Delegación**: Permite que el servidor suplante al cliente en sistemas remotos cuando el mecanismo de autenticación y la configuración de la cuenta admiten la delegación.

#### Evaluar un token capturado antes de usarlo

No selecciones un token basándote solo en el nombre de usuario. La misma cuenta puede tener varios tokens con distintas sesiones de inicio de sesión, SIDs de servicio, privilegios, niveles de integridad, restricciones y credenciales de red.<sup>[[9]](#references)</sup> Consulta como mínimo **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** y **`TokenStatistics.AuthenticationId`** con `GetTokenInformation`.<sup>[[7]](#references)</sup>

Un token restringido puede contener SIDs de solo denegación, privilegios eliminados y SIDs restrictivos. Cuando hay SIDs restrictivos, Windows realiza una comprobación de acceso con los SIDs habilitados y otra con los SIDs restrictivos; **ambas comprobaciones deben permitir el acceso**. Por lo tanto, que aparezca un SID de usuario atractivo o un grupo habilitado no demuestra por sí solo que el token pueda acceder al objeto de destino.<sup>[[8]](#references)</sup>

Sigue este flujo de decisión para cumplir los requisitos documentados de tokens y creación de procesos:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Un **token primario** necesita un identificador con `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` antes de poder proporcionarse a `CreateProcessWithTokenW` o `CreateProcessAsUserW`.
2. Convierte un **token de suplantación** con `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Los tokens de nivel de identificación pueden exponer datos de identidad, pero no pueden realizar comprobaciones de acceso como ese cliente.
3. `CreateProcessWithTokenW` necesita `SeImpersonatePrivilege` e inicia el proceso hijo en la sesión del llamador. En cambio, `CreateProcessAsUserW` usa la sesión del token, pero normalmente necesita `SeIncreaseQuotaPrivilege` y puede necesitar `SeAssignPrimaryTokenPrivilege`. Si hay credenciales disponibles y faltan estos privilegios, `CreateProcessWithLogonW` es la alternativa documentada.

#### Buscar identificadores de token, no solo propietarios de procesos

Abrir el token primario de cada proceso puede pasar por alto **tokens de suplantación conservados como identificadores ordinarios** dentro de servicios y procesos intermediarios. Un flujo de trabajo reutilizable para las tablas de identificadores consiste en enumerar los identificadores del sistema, filtrar los objetos de tipo token, abrir cada propietario con `PROCESS_DUP_HANDLE`, duplicar el identificador candidato en el proceso actual y, luego, consultar los campos anteriores. Confirma que el identificador duplicado incluya `TOKEN_QUERY` y `TOKEN_DUPLICATE`; ver un identificador de token no significa que pueda duplicarse para obtener un token primario utilizable. Los procesos protegidos y las DACL de procesos aún pueden impedir el acceso al identificador del proceso propietario.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatiza la enumeración de tokens primarios de procesos y de identificadores de token conservados. `list_token` mantiene un candidato preferido por nombre de usuario, mientras que `list_all_token` muestra todos los candidatos. Un PID limita la enumeración a un único proceso propietario.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Para la inspección manual y la comprobación de acceso, **TokenUniverse** puede abrir tokens de procesos/hilos, buscar identificadores de token existentes, inspeccionar restricciones y sesiones de inicio de sesión, duplicar tokens y probar varios métodos de creación de procesos.<sup>[[13]](#references)</sup> Para la primitiva subyacente de identificadores entre procesos, consulta:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Buscar tokens de suplantación de hilos activos

Un hilo de servicio puede suplantar temporalmente a un cliente aunque su **token principal de proceso** pertenezca a la cuenta del servicio, por lo que los análisis basados en el propietario del proceso pueden pasar por alto el contexto del cliente.<sup>[[4]](#references)</sup> TokenUniverse puede enumerar los tokens accesibles de procesos/hilos; en System Informer, inspecciona la pestaña **Threads** de un proceso y su columna **Impersonation** para encontrar hilos candidatos.<sup>[[13]](#references)[[14]](#references)</sup>

Para una comprobación dirigida mediante API, toma una instantánea `TH32CS_SNAPTHREAD`, filtra `THREADENTRY32.th32OwnerProcessID` por el PID del servicio y luego llama a `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` y `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` para cada hilo accesible.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` hace que la comprobación de acceso al abrir el token use el contexto de **proceso** del llamador, lo cual importa si el propio escáner está suplantando a nivel de identificación.<sup>[[17]](#references)</sup> Consulta el usuario, el tipo, el nivel de suplantación y el ID de inicio de sesión del token antes de probar el flujo de duplicación/creación de procesos anterior.<sup>[[7]](#references)</sup> Un hilo puede dejar de suplantar entre la enumeración y la apertura; la ausencia de token, los tokens anónimos, los hilos protegidos, las DACL de hilos y las DACL de tokens pueden impedir la recopilación.<sup>[[16]](#references)[[17]](#references)</sup> A diferencia del análisis de los identificadores de token conservados por un servicio, esto comprueba el **token de hilo asignado actualmente**.

Para una vía de ataque que obtiene un token de hilo haciendo que un cliente privilegiado se conecte a tu pipe, en lugar de analizar los hilos existentes, consulta [suplantación de clientes de named pipes](named-pipe-client-impersonation.md).

#### Suplantar tokens

Si tienes privilegios suficientes, con el módulo _**incognito**_ de metasploit puedes **enumerar** y **suplantar** fácilmente otros **tokens**. Esto puede ser útil para realizar **acciones como si fueras el otro usuario**. También podrías **escalar privilegios** con esta técnica.

Algunos consejos prácticos que es fácil olvidar durante la operación:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** requiere **`SeImpersonatePrivilege`** en el llamador y el nuevo proceso se ejecutará en la **sesión del llamador**.
- **`CreateProcessAsUserW`** es una posible alternativa cuando `CreateProcessWithTokenW` falla con `1314`, pero solo si el llamador cumple los requisitos de privilegios. También es la opción correcta cuando el proceso hijo debe ejecutarse en la **sesión a la que hace referencia el token**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** devuelve un **token de suplantación**. Conviértelo con **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de crear el proceso. Incluso después de la conversión, el proceso resultante no puede usar ese inicio de sesión de red para acceder a recursos compartidos o impresoras remotos autenticados: este tipo de inicio de sesión no almacena credenciales en caché. Si tienes credenciales y necesitas acceso posterior a la red, usa un inicio de sesión interactivo o de texto no cifrado de red; no lo confundas con `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), que mantiene la identidad local y proporciona credenciales salientes.<sup>[[18]](#references)</sup>
- No todos los tokens de suplantación son igual de útiles: **`SecurityIdentification`** te permite inspeccionar al usuario, pero **no actuar como él**. Si una primitiva de coerción o un cliente de pipe/RPC te proporciona solo un token de nivel de identificación, comprueba **`TokenImpersonationLevel`** y cambia a una primitiva que proporcione **`SecurityImpersonation`** o un nivel superior.

#### Robo de tokens sin tocar LSASS

Si ya tienes un contexto de **servicio** o **SYSTEM** y hay un **usuario privilegiado con sesión iniciada**, robar o duplicar el token de ese usuario suele ser más discreto que volcar **LSASS**. En muchas intrusiones reales, esto basta para:<sup>[[2]](#references)</sup>

- ejecutar acciones locales como ese usuario
- acceder a recursos remotos como ese usuario
- realizar operaciones de AD sin extraer primero credenciales reutilizables

Para ver ejemplos de **secuestro de tokens de sesión/usuario** desde un contexto privilegiado, consulta [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Recuerda que las API como **`WTSQueryUserToken`** están destinadas a **servicios altamente confiables** y normalmente requieren **`LocalSystem` + `SeTcbPrivilege`**, por lo que son principalmente útiles cuando ya controlas un contexto de nivel de servicio. Para conocer formas de obtener primero **SYSTEM** mediante privilegios específicos, consulta las páginas siguientes.

### Privilegios de token

Descubre qué **privilegios de token se pueden abusar para escalar privilegios:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Consulta [**todos los privilegios de token posibles y algunas definiciones en esta página externa**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Comprender y abusar de los tokens de acceso — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusar de los tokens de Windows para comprometer Active Directory sin tocar LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Desmitificando el comando "make_token" de Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Tokens de acceso - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Cómo funciona el Control de cuentas de usuario - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Niveles de suplantación - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumeración TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokens restringidos - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Función CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Función CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Función DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Solicitud de función de tokens de hilo de System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Recorrer la lista de hilos - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
