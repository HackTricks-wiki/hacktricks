# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Einführung

Das Kerberos-Problem „Double Hop“ tritt auf, wenn ein Angreifer versucht, **Kerberos-Authentifizierung über zwei** **Hops** hinweg zu verwenden, beispielsweise mit **PowerShell**/**WinRM**.

Wenn eine **Authentifizierung** über **Kerberos** erfolgt, werden **Anmeldeinformationen** **nicht** im **Arbeitsspeicher** zwischengespeichert. Wenn du daher mimikatz ausführst, **wirst du keine Anmeldeinformationen** des Benutzers auf dem Computer finden, selbst wenn dieser Prozesse ausführt.

Der Grund dafür ist, dass bei einer Verbindung mit Kerberos folgende Schritte ausgeführt werden:<sup>[[1]](#references)</sup>

1. User1 stellt Anmeldeinformationen bereit und der **Domain Controller** gibt User1 ein Kerberos-**TGT** zurück.
2. User1 verwendet das **TGT**, um ein **Service-Ticket** anzufordern und sich mit Server1 zu **verbinden**.
3. User1 **verbindet sich** mit **Server1** und stellt das **Service-Ticket** bereit.
4. **Server1** hat weder die **Anmeldeinformationen** von User1 noch das **TGT** von User1 zwischengespeichert. Wenn User1 daher von Server1 aus versucht, sich bei einem zweiten Server anzumelden, kann er sich **nicht authentifizieren**.

### Unconstrained Delegation

Wenn **unconstrained delegation** auf dem PC aktiviert ist, tritt dieses Problem nicht auf, da der **Server** ein **TGT** jedes Benutzers erhält, der darauf zugreift. Wenn außerdem unconstrained delegation verwendet wird, kannst du den **Domain Controller** darüber wahrscheinlich **kompromittieren**.\
[**Weitere Informationen auf der Seite zu unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Eine weitere Möglichkeit, dieses Problem zu vermeiden, ist der [**besonders unsichere**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**. Von Microsoft:

> Die CredSSP-Authentifizierung delegiert die Anmeldeinformationen des Benutzers vom lokalen Computer an einen Remotecomputer. Diese Vorgehensweise erhöht das Sicherheitsrisiko des Remotevorgangs. Wenn der Remotecomputer kompromittiert wird, können die an ihn übergebenen Anmeldeinformationen zur Kontrolle der Netzwerksitzung verwendet werden.

Es wird dringend empfohlen, **CredSSP** auf Produktionssystemen, in sensiblen Netzwerken und in ähnlichen Umgebungen aufgrund von Sicherheitsbedenken zu deaktivieren. Um festzustellen, ob **CredSSP** aktiviert ist, kann der Befehl `Get-WSManCredSSP` ausgeführt werden. Dieser Befehl ermöglicht die **Überprüfung des CredSSP-Status** und kann sogar remote ausgeführt werden, sofern **WinRM** aktiviert ist.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** hält das TGT des Benutzers weiterhin auf der ursprünglichen Workstation, ermöglicht der RDP-Sitzung jedoch, im nächsten Hop neue Kerberos service tickets anzufordern. Aktivieren Sie **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** und wählen Sie **Require Remote Credential Guard** aus. Stellen Sie anschließend mit `mstsc.exe /remoteGuard /v:server1` eine Verbindung her, anstatt auf CredSSP zurückzufallen.

Microsoft hat RCG für den Multi-Hop-Zugriff unter Windows 11 22H2+ bis zu den **kumulativen Updates vom April 2024** (KB5036896/KB5036899/KB5036894) funktionsunfähig gemacht. Installieren Sie die Patches auf dem Client und dem zwischengeschalteten Server, andernfalls schlägt der zweite Hop weiterhin fehl.<sup>[[5]](#references)</sup> Schneller Hotfix-Check:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Mit diesen Builds kann der RDP hop nachgelagerte Kerberos-Herausforderungen erfüllen, ohne wiederverwendbare Secrets auf dem ersten Server offenzulegen.

## Workarounds

### Invoke Command

Um das Double-Hop-Problem zu beheben, wird eine Methode mit einem verschachtelten `Invoke-Command` vorgestellt. Dies löst das Problem nicht direkt, bietet jedoch einen Workaround, ohne dass spezielle Konfigurationen erforderlich sind. Dieser Ansatz ermöglicht die Ausführung eines Befehls (`hostname`) auf einem sekundären Server über einen PowerShell-Befehl, der von einer initialen angreifenden Maschine oder über eine zuvor eingerichtete PS-Session mit dem ersten Server ausgeführt wird. So wird es durchgeführt:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativ wird empfohlen, eine PS-Session mit dem ersten Server aufzubauen und `Invoke-Command` mit `$cred` auszuführen, um Aufgaben zu zentralisieren.

### Register PSSession Configuration

Eine Lösung zur Umgehung des double hop problem besteht darin, `Register-PSSessionConfiguration` zusammen mit `Enter-PSSession` zu verwenden. Diese Methode erfordert einen anderen Ansatz als `evil-winrm` und ermöglicht eine Session, die nicht unter der double hop limitation leidet.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Für lokale Administratoren auf einem Zwischenziel ermöglicht Port forwarding das Senden von Anfragen an einen endgültigen Server. Mit `netsh` kann eine Regel für Port forwarding hinzugefügt werden, zusammen mit einer Windows-Firewallregel, die den weitergeleiteten Port erlaubt.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kann zum Weiterleiten von WinRM-Anfragen verwendet werden und ist möglicherweise eine weniger auffällige Option, wenn die PowerShell-Überwachung ein Problem darstellt.<sup>[[2]](#references)</sup> Der folgende Befehl veranschaulicht seine Verwendung:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die Installation von OpenSSH auf dem ersten Server ermöglicht eine Umgehung des Double-Hop-Problems und ist besonders für Jump-Box-Szenarien nützlich. Diese Methode erfordert die Installation und Einrichtung von OpenSSH für Windows über die CLI. Bei der Konfiguration mit Password Authentication kann der Zwischenserver im Namen des Benutzers ein TGT beziehen.<sup>[[2]](#references)</sup>

#### Schritte zur OpenSSH-Installation

1. Lade das ZIP-Archiv der neuesten OpenSSH-Version herunter und verschiebe es auf den Zielserver.
2. Entpacke es und führe das Skript `Install-sshd.ps1` aus.
3. Füge eine Firewall-Regel hinzu, um Port 22 zu öffnen, und überprüfe, ob die SSH-Dienste ausgeführt werden.

Um Fehler wie `Connection reset` zu beheben, müssen möglicherweise die Berechtigungen aktualisiert werden, damit jeder Lese- und Ausführzugriff auf das OpenSSH-Verzeichnis erhält.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) legt den `msv1_0!CacheLogon`-Package-Call offen, sodass du einen bestehenden *network logon* mit einem bekannten NT hash versehen kannst, anstatt mit `LogonUser` eine neue Session zu erstellen. Indem du den Hash in die Logon-Session injizierst, die WinRM/PowerShell bereits auf Hop #1 geöffnet hat, kann dieser Host sich bei Hop #2 authentifizieren, ohne explizite Credentials zu speichern oder zusätzliche 4624-Events zu erzeugen.<sup>[[6]](#references)</sup>

1. Erhalte Codeausführung innerhalb von LSASS (deaktiviere/abuse dazu entweder PPL oder führe den Vorgang auf einer von dir kontrollierten Lab-VM aus).
2. Enumeriere die Logon-Sessions (z. B. `lsa.exe sessions`) und ermittle die LUID, die deinem Remoting-Kontext entspricht.
3. Berechne den NT hash vorab und übergib ihn an `CacheLogon`; lösche ihn anschließend.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Nach dem cache seed führe `Invoke-Command`/`New-PSSession` von Hop #1 erneut aus: LSASS verwendet den injizierten Hash wieder, um Kerberos-/NTLM-Herausforderungen für den zweiten Hop zu erfüllen, und umgeht damit elegant die Double-Hop-Einschränkung. Der Nachteil ist eine umfangreichere Telemetrie (Code execution in LSASS). Verwende diese Methode daher in Umgebungen mit hohen Einschränkungen, in denen CredSSP/RCG nicht erlaubt sind.

## Referenzen

- [1] [Kerberos Double Hop verstehen – Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Lösungen für Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Eine weitere Lösung für PowerShell-Remoting über mehrere Hops](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Das PowerShell-Multi-Hop-Problem ohne CredSSP lösen](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9. April 2024 – KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
