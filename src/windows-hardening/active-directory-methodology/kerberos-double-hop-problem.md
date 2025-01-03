# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}

## Einführung

Das Kerberos "Double Hop" Problem tritt auf, wenn ein Angreifer versucht, **Kerberos-Authentifizierung über zwei** **Hops** zu verwenden, zum Beispiel mit **PowerShell**/**WinRM**.

Wenn eine **Authentifizierung** über **Kerberos** erfolgt, werden **Anmeldeinformationen** **nicht** im **Speicher** zwischengespeichert. Daher werden Sie, wenn Sie mimikatz ausführen, **keine Anmeldeinformationen** des Benutzers auf der Maschine finden, selbst wenn er Prozesse ausführt.

Das liegt daran, dass beim Verbinden mit Kerberos folgende Schritte durchgeführt werden:

1. Benutzer1 gibt Anmeldeinformationen ein und der **Domänencontroller** gibt ein Kerberos **TGT** an Benutzer1 zurück.
2. Benutzer1 verwendet das **TGT**, um ein **Dienstticket** anzufordern, um sich mit Server1 zu **verbinden**.
3. Benutzer1 **verbindet** sich mit **Server1** und gibt das **Dienstticket** an.
4. **Server1** hat **keine** Anmeldeinformationen von Benutzer1 zwischengespeichert oder das **TGT** von Benutzer1. Daher kann Benutzer1 von Server1 aus nicht auf einen zweiten Server zugreifen, da er sich **nicht authentifizieren kann**.

### Unbeschränkte Delegierung

Wenn die **unbeschränkte Delegierung** auf dem PC aktiviert ist, tritt dies nicht auf, da der **Server** ein **TGT** für jeden Benutzer erhält, der darauf zugreift. Darüber hinaus können Sie, wenn unbeschränkte Delegierung verwendet wird, wahrscheinlich den **Domänencontroller** von dort aus **kompromittieren**.\
[**Weitere Informationen auf der Seite zur unbeschränkten Delegierung**](unconstrained-delegation.md).

### CredSSP

Eine weitere Möglichkeit, dieses Problem zu vermeiden, die [**auffällig unsicher**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) ist, ist der **Credential Security Support Provider**. Von Microsoft:

> CredSSP-Authentifizierung delegiert die Benutzeranmeldeinformationen vom lokalen Computer an einen Remote-Computer. Diese Praxis erhöht das Sicherheitsrisiko der Remote-Operation. Wenn der Remote-Computer kompromittiert wird, können die Anmeldeinformationen, wenn sie an ihn übergeben werden, verwendet werden, um die Netzwerksitzung zu steuern.

Es wird dringend empfohlen, dass **CredSSP** auf Produktionssystemen, sensiblen Netzwerken und ähnlichen Umgebungen aus Sicherheitsgründen deaktiviert wird. Um festzustellen, ob **CredSSP** aktiviert ist, kann der Befehl `Get-WSManCredSSP` ausgeführt werden. Dieser Befehl ermöglicht die **Überprüfung des CredSSP-Status** und kann sogar remote ausgeführt werden, vorausgesetzt, **WinRM** ist aktiviert.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Um das Double-Hop-Problem zu beheben, wird eine Methode vorgestellt, die ein geschachteltes `Invoke-Command` verwendet. Dies löst das Problem nicht direkt, bietet jedoch eine Umgehungslösung, ohne spezielle Konfigurationen zu benötigen. Der Ansatz ermöglicht es, einen Befehl (`hostname`) auf einem sekundären Server über einen PowerShell-Befehl auszuführen, der von einer anfänglichen angreifenden Maschine oder über eine zuvor eingerichtete PS-Session mit dem ersten Server ausgeführt wird. So wird es gemacht:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativ wird empfohlen, eine PS-Session mit dem ersten Server einzurichten und `Invoke-Command` mit `$cred` auszuführen, um Aufgaben zu zentralisieren.

### PSSession-Konfiguration registrieren

Eine Lösung zur Umgehung des Double-Hop-Problems besteht darin, `Register-PSSessionConfiguration` mit `Enter-PSSession` zu verwenden. Diese Methode erfordert einen anderen Ansatz als `evil-winrm` und ermöglicht eine Sitzung, die nicht unter der Double-Hop-Beschränkung leidet.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Für lokale Administratoren auf einem Zwischenziel ermöglicht das Port-Forwarding, Anfragen an einen endgültigen Server zu senden. Mit `netsh` kann eine Regel für das Port-Forwarding hinzugefügt werden, zusammen mit einer Windows-Firewallregel, um den weitergeleiteten Port zuzulassen.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kann verwendet werden, um WinRM-Anfragen weiterzuleiten, möglicherweise als weniger erkennbare Option, wenn die Überwachung von PowerShell ein Anliegen ist. Der folgende Befehl zeigt seine Verwendung:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die Installation von OpenSSH auf dem ersten Server ermöglicht eine Umgehung des Double-Hop-Problems, das besonders nützlich für Jump-Box-Szenarien ist. Diese Methode erfordert die CLI-Installation und -Einrichtung von OpenSSH für Windows. Wenn es für die Passwortauthentifizierung konfiguriert ist, ermöglicht dies dem Zwischenserver, ein TGT im Namen des Benutzers zu erhalten.

#### OpenSSH Installationsschritte

1. Laden Sie die neueste OpenSSH-Release-Zip-Datei herunter und verschieben Sie sie auf den Zielserver.
2. Entpacken Sie die Datei und führen Sie das Skript `Install-sshd.ps1` aus.
3. Fügen Sie eine Firewall-Regel hinzu, um Port 22 zu öffnen, und überprüfen Sie, ob die SSH-Dienste ausgeführt werden.

Um `Connection reset`-Fehler zu beheben, müssen möglicherweise die Berechtigungen aktualisiert werden, um allen Lese- und Ausführungszugriff auf das OpenSSH-Verzeichnis zu gewähren.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referenzen

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
