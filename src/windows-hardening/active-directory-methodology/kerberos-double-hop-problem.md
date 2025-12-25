# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Einführung

The Kerberos "Double Hop" problem appears when an attacker attempts to use **Kerberos authentication across two** **hops**, for example using **PowerShell**/**WinRM**.

Wenn eine Authentifizierung über Kerberos erfolgt, werden Anmeldedaten nicht im Speicher gecached. Daher findest du beim Ausführen von mimikatz keine Anmeldedaten des Benutzers auf dem Rechner, selbst wenn er Prozesse ausführt.

Das liegt daran, dass beim Verbinden mit Kerberos folgende Schritte ablaufen:

1. User1 provides credentials and **domain controller** returns a Kerberos **TGT** to the User1.
2. User1 uses **TGT** to request a **service ticket** to **connect** to Server1.
3. User1 **connects** to **Server1** and provides **service ticket**.
4. **Server1** **doesn't** have **credentials** of User1 cached or the **TGT** of User1. Therefore, when User1 from Server1 tries to login to a second server, he is **not able to authenticate**.

### Unconstrained Delegation

If **unconstrained delegation** is enabled in the PC, this won't happen as the **Server** will **get** a **TGT** of each user accessing it. Moreover, if unconstrained delegation is used you probably can **compromise the Domain Controller** from it.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. From Microsoft:

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

Es wird dringend empfohlen, CredSSP in Produktionssystemen, sensiblen Netzwerken und ähnlichen Umgebungen aufgrund von Sicherheitsbedenken zu deaktivieren. Um festzustellen, ob CredSSP aktiviert ist, kann der Befehl `Get-WSManCredSSP` ausgeführt werden. Dieser Befehl ermöglicht die Überprüfung des CredSSP-Status und kann sogar remote ausgeführt werden, sofern **WinRM** aktiviert ist.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** behält das TGT des Benutzers auf der ursprünglichen Workstation, erlaubt aber trotzdem, dass die RDP-Session neue Kerberos-Service-Tickets für den nächsten Hop anfordert. Aktivieren Sie **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** und wählen Sie **Require Remote Credential Guard** aus, verbinden Sie sich dann mit `mstsc.exe /remoteGuard /v:server1` statt auf CredSSP zurückzufallen.

Microsoft hat RCG für Multi-Hop-Zugriff unter Windows 11 22H2+ bis zu den **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894) gebrochen. Patchen Sie den Client und den Zwischenserver, sonst wird der zweite Hop weiterhin fehlschlagen. Schnelle Hotfix-Prüfung:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Wenn diese Builds installiert sind, kann der RDP‑Hop nachgelagerte Kerberos‑Anforderungen erfüllen, ohne wiederverwendbare Geheimnisse auf dem ersten Server preiszugeben.

## Umgehungen

### Invoke Command

Um das double hop-Problem anzugehen, wird eine Methode mit einem verschachtelten `Invoke-Command` vorgestellt. Das löst das Problem nicht direkt, bietet jedoch eine Umgehungslösung, ohne spezielle Konfigurationen zu benötigen. Der Ansatz ermöglicht das Ausführen eines Befehls (`hostname`) auf einem sekundären Server über einen PowerShell-Befehl, der von einer anfänglichen Angreifermaschine ausgeführt wird oder über eine zuvor eingerichtete PS-Session mit dem ersten Server. So wird es gemacht:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativ wird empfohlen, eine PS-Session mit dem ersten Server zu erstellen und den `Invoke-Command` mit `$cred` auszuführen, um Aufgaben zu zentralisieren.

### Register PSSession Configuration

Eine Lösung, um das Double-Hop-Problem zu umgehen, besteht darin, `Register-PSSessionConfiguration` zusammen mit `Enter-PSSession` zu verwenden. Diese Methode erfordert einen anderen Ansatz als `evil-winrm` und ermöglicht eine Sitzung, die nicht unter der Double-Hop-Einschränkung leidet.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Für lokale Administratoren auf einem Zwischenziel ermöglicht port forwarding, dass Anfragen an einen Zielserver gesendet werden. Mit `netsh` kann eine Regel für port forwarding hinzugefügt werden, sowie eine Windows firewall-Regel, um den weitergeleiteten Port zuzulassen.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kann verwendet werden, um WinRM-Anfragen weiterzuleiten, möglicherweise als weniger erkennbare Option, wenn PowerShell-Überwachung ein Problem ist. Der folgende Befehl zeigt seine Verwendung:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die Installation von OpenSSH auf dem ersten Server ermöglicht einen Workaround für das Double-Hop-Problem und ist besonders nützlich bei Jump-Box-Szenarien. Diese Methode erfordert die Installation und Einrichtung von OpenSSH für Windows über die CLI. Wenn für Password Authentication konfiguriert, kann der Vermittlungsserver ein TGT im Namen des Benutzers erhalten.

#### OpenSSH Installationsschritte

1. Lade das neueste OpenSSH-Release-Zip herunter und verschiebe es auf den Zielserver.
2. Entpacke die Datei und führe das Skript `Install-sshd.ps1` aus.
3. Füge eine Firewall-Regel hinzu, um Port 22 zu öffnen, und überprüfe, dass die SSH-Services laufen.

Um `Connection reset`-Fehler zu beheben, müssen möglicherweise die Berechtigungen angepasst werden, damit die Gruppe Everyone Lese- und Ausführungsrechte für das OpenSSH-Verzeichnis erhält.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Fortgeschritten)

**LSA Whisperer** (2024) legt den `msv1_0!CacheLogon` Paketaufruf offen, sodass du eine bestehende *Netzwerk-Anmeldung* mit einem bekannten NT hash versorgen kannst, anstatt eine neue Sitzung mit `LogonUser` zu erstellen. Indem du den Hash in die Anmeldesitzung injizierst, die WinRM/PowerShell bereits auf hop #1 geöffnet hat, kann dieser Host sich zu hop #2 authentifizieren, ohne explizite Anmeldeinformationen zu speichern oder zusätzliche 4624-Ereignisse zu erzeugen.

1. Verschaffe dir Codeausführung innerhalb von LSASS (entweder PPL deaktivieren/ausnutzen oder auf einer Lab-VM ausführen, die du kontrollierst).
2. Liste Anmeldesitzungen auf (z. B. `lsa.exe sessions`) und erfasse die LUID, die deinem Remoting-Kontext entspricht.
3. Berechne im Voraus den NT hash und übergebe ihn an `CacheLogon`, dann lösche ihn, wenn du fertig bist.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Nach dem cache seed, führe `Invoke-Command`/`New-PSSession` von hop #1 erneut aus: LSASS wird den injizierten Hash wiederverwenden, um Kerberos/NTLM-Challenges für den zweiten hop zu erfüllen und damit elegant die double hop-Einschränkung zu umgehen. Der Nachteil ist stärkere Telemetrie (Codeausführung in LSASS), daher nur in stark restriktiven Umgebungen verwenden, in denen CredSSP/RCG nicht erlaubt sind.

## Referenzen

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
